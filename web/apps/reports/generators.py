"""Report export generators — HTML, PDF (WeasyPrint), JSON, Markdown.

Professional pentest report with 6 core sections:
  1. Executive Summary    — overall risk posture & severity distribution
  2. Testing Methodology  — modules used, WSTG v4.2 coverage, tooling
  3. Scope of Work (SoW)  — all assessed targets and in-scope domains
  4. Findings Summary     — consolidated vulnerability table
  5. Detailed Findings    — CVSS v3.1, CVE/NVD, Evidence/PoC, Recommendations
  6. WSTG v4.2 Playbook   — full testing checklist with coverage status
"""
from __future__ import annotations

import json
from datetime import date
from typing import TYPE_CHECKING

from django.db import models

if TYPE_CHECKING:
    from apps.reports.models import Report


# ─── Module Registry ──────────────────────────────────────────────────────────
# Maps module_id → (display_name, category, [wstg_ref, ...])
MODULE_REGISTRY: dict[str, tuple[str, str, list[str]]] = {
    # Reconnaissance
    "R-01":  ("Port Scanner",               "Reconnaissance", ["WSTG-CONF-06"]),
    "R-02":  ("Subdomain Enumeration",      "Reconnaissance", ["WSTG-INFO-04"]),
    "R-03":  ("SSL/TLS Deep Audit",         "Reconnaissance", ["WSTG-CRYP-01", "WSTG-CONF-07"]),
    "R-04":  ("WAF & CDN Fingerprint",      "Reconnaissance", ["WSTG-INFO-09"]),
    "R-05":  ("Tech Stack Fingerprint",     "Reconnaissance", ["WSTG-INFO-02", "WSTG-INFO-08"]),
    "R-06":  ("DNS Full Enumeration",       "Reconnaissance", ["WSTG-INFO-05"]),
    "R-07":  ("Certificate Transparency",   "Reconnaissance", ["WSTG-CRYP-01"]),
    "R-08":  ("Web Crawler & Sitemap",      "Reconnaissance", ["WSTG-INFO-06", "WSTG-INFO-07"]),
    "R-09":  ("HTTP Probing",               "Reconnaissance", ["WSTG-INFO-01", "WSTG-INFO-09"]),
    "R-10":  ("ASN & IP Intelligence",      "Reconnaissance", ["WSTG-INFO-10"]),
    "R-11":  ("Email Harvesting",           "Reconnaissance", ["WSTG-INFO-01"]),
    "R-12":  ("Google Dork Automation",     "Reconnaissance", ["WSTG-INFO-01"]),
    "R-13":  ("GitHub Recon",               "Reconnaissance", ["WSTG-INFO-01", "WSTG-CONF-05"]),
    "R-14":  ("Shodan / Censys Intelligence","Reconnaissance", ["WSTG-INFO-01"]),
    "R-15":  ("Cloud Asset Discovery",      "Reconnaissance", ["WSTG-CONF-11"]),
    "R-16":  ("Virtual Host Discovery",     "Reconnaissance", ["WSTG-INFO-04"]),
    "R-17":  ("Screenshot Capture",         "Reconnaissance", []),
    # Injection
    "I-01":  ("SQL Injection",              "Injection Attacks", ["WSTG-INPV-05"]),
    "I-02":  ("NoSQL Injection",            "Injection Attacks", ["WSTG-INPV-05"]),
    "I-03":  ("LDAP Injection",             "Injection Attacks", ["WSTG-INPV-06"]),
    "I-04":  ("XPath Injection",            "Injection Attacks", ["WSTG-INPV-09"]),
    "I-05":  ("Command Injection",          "Injection Attacks", ["WSTG-INPV-12"]),
    "I-06":  ("SSTI / Template Injection",  "Injection Attacks", ["WSTG-INPV-18"]),
    "I-07":  ("HTML Injection",             "Injection Attacks", ["WSTG-CLNT-03"]),
    "I-08":  ("Email Header Injection",     "Injection Attacks", ["WSTG-INPV-10"]),
    "I-09":  ("HTTP Parameter Pollution",   "Injection Attacks", ["WSTG-INPV-04"]),
    "I-10":  ("XML/SOAP Injection",         "Injection Attacks", ["WSTG-INPV-07"]),
    # XSS
    "X-01":  ("Reflected XSS Scanner",     "Cross-Site Scripting", ["WSTG-INPV-01"]),
    "X-02":  ("Stored XSS",                "Cross-Site Scripting", ["WSTG-INPV-02"]),
    "X-03":  ("DOM XSS Finder",            "Cross-Site Scripting", ["WSTG-CLNT-01"]),
    "X-04":  ("Blind XSS (OOB)",           "Cross-Site Scripting", ["WSTG-INPV-02"]),
    "X-05":  ("mXSS / Mutation XSS",       "Cross-Site Scripting", ["WSTG-INPV-01"]),
    "X-06":  ("CSS Injection",             "Cross-Site Scripting", ["WSTG-CLNT-05"]),
    "X-07":  ("XSS via File Upload",       "Cross-Site Scripting", ["WSTG-INPV-13"]),
    "X-08":  ("XSS WAF Bypass Lab",        "Cross-Site Scripting", ["WSTG-INPV-01"]),
    # Server-Side Attacks
    "SS-01": ("SSRF",                      "Server-Side Attacks", ["WSTG-INPV-19"]),
    "SS-02": ("XXE Injection",             "Server-Side Attacks", ["WSTG-INPV-07"]),
    "SS-03": ("File Upload RCE",           "Server-Side Attacks", ["WSTG-INPV-13"]),
    "SS-04": ("Insecure Deserialization",  "Server-Side Attacks", ["WSTG-INPV-11"]),
    "SS-05": ("Path Traversal / LFI",      "Server-Side Attacks", ["WSTG-ATHZ-01", "WSTG-INPV-15"]),
    "SS-06": ("Remote File Inclusion",     "Server-Side Attacks", ["WSTG-INPV-11"]),
    "SS-07": ("Open Redirect",             "Server-Side Attacks", ["WSTG-CLNT-04"]),
    "SS-08": ("SSTI to RCE",               "Server-Side Attacks", ["WSTG-INPV-18"]),
    "SS-09": ("Log Poisoning",             "Server-Side Attacks", ["WSTG-INPV-15"]),
    # Authentication
    "AUTH-01": ("JWT Full Attack Suite",   "Authentication Testing", ["WSTG-SESS-10", "WSTG-ATHN-01"]),
    "AUTH-02": ("OAuth2 Vulnerability",    "Authentication Testing", ["WSTG-ATHN-01"]),
    "AUTH-03": ("SAML Attacks",            "Authentication Testing", ["WSTG-ATHN-01"]),
    "AUTH-04": ("Password Brute Force",    "Authentication Testing", ["WSTG-ATHN-07", "WSTG-ATHN-03"]),
    "AUTH-05": ("Credential Stuffing",     "Authentication Testing", ["WSTG-ATHN-01"]),
    "AUTH-06": ("MFA/2FA Bypass",          "Authentication Testing", ["WSTG-ATHN-01"]),
    "AUTH-07": ("Session Management Audit","Authentication Testing", ["WSTG-SESS-01", "WSTG-SESS-02"]),
    "AUTH-08": ("Password Reset Flaws",    "Authentication Testing", ["WSTG-ATHN-09", "WSTG-ATHN-10"]),
    "AUTH-09": ("Account Takeover Chain",  "Authentication Testing", ["WSTG-ATHN-01"]),
    "AUTH-10": ("SSO / OIDC Abuse",        "Authentication Testing", ["WSTG-ATHN-01"]),
    # Access Control
    "AC-01": ("IDOR / BOLA",               "Access Control Testing", ["WSTG-ATHZ-04"]),
    "AC-02": ("BFLA / Function-Level Auth Bypass", "Access Control Testing", ["WSTG-ATHZ-02"]),
    "AC-03": ("Privilege Escalation",      "Access Control Testing", ["WSTG-ATHZ-03"]),
    "AC-04": ("Directory Traversal",       "Access Control Testing", ["WSTG-ATHZ-01"]),
    "AC-05": ("Forced Browsing",           "Access Control Testing", ["WSTG-ATHZ-02"]),
    "AC-06": ("HTTP Method Override",      "Access Control Testing", ["WSTG-CONF-06"]),
    "AC-07": ("Missing Function-Level Auth","Access Control Testing", ["WSTG-ATHZ-02"]),
    "AC-08": ("JWT Privilege Escalation",  "Access Control Testing", ["WSTG-ATHZ-03", "WSTG-SESS-10"]),
    # Business Logic
    "BL-01": ("Race Condition Engine",     "Business Logic Testing", ["WSTG-BUSL-08"]),
    "BL-02": ("Price / Value Manipulation","Business Logic Testing", ["WSTG-BUSL-06"]),
    "BL-03": ("Workflow Step Bypass",      "Business Logic Testing", ["WSTG-BUSL-04", "WSTG-BUSL-06"]),
    "BL-04": ("Limit Bypass",              "Business Logic Testing", ["WSTG-BUSL-05"]),
    "BL-05": ("Coupon / Promo Abuse",      "Business Logic Testing", ["WSTG-BUSL-06"]),
    "BL-06": ("File Upload Logic Bypass",  "Business Logic Testing", ["WSTG-BUSL-08", "WSTG-BUSL-09"]),
    "BL-07": ("2FA Race Condition",        "Business Logic Testing", ["WSTG-BUSL-08"]),
    "BL-08": ("Account & Balance Exploit", "Business Logic Testing", ["WSTG-BUSL-06"]),
    # API Security
    "API-01": ("REST API Fuzzer",          "API Security Testing", ["WSTG-APIT-02"]),
    "API-02": ("API Version Enumeration",  "API Security Testing", ["WSTG-INFO-07"]),
    "API-03": ("Mass Assignment",          "API Security Testing", ["WSTG-APIT-02"]),
    "API-04": ("Rate Limit Bypass",        "API Security Testing", ["WSTG-BUSL-05"]),
    "API-05": ("API Key Leak Scanner",     "API Security Testing", ["WSTG-CONF-05"]),
    "API-06": ("GraphQL Security Suite",   "API Security Testing", ["WSTG-APIT-01"]),
    "API-07": ("SOAP / WSDL Audit",        "API Security Testing", ["WSTG-APIT-02"]),
    "API-08": ("WebSocket Fuzzer",         "API Security Testing", ["WSTG-CLNT-10"]),
    "API-09": ("gRPC Security Audit",      "API Security Testing", ["WSTG-APIT-02"]),
    "API-10": ("JSON Web API Injection",   "API Security Testing", ["WSTG-INPV-05"]),
    "API-11": ("API Object-Level Authorization (BOLA)", "API Security Testing", ["WSTG-ATHZ-04"]),
    "API-12": ("Swagger/OpenAPI Parser",   "API Security Testing", ["WSTG-INFO-07"]),
    # Client-Side
    "CS-01": ("CSRF",                      "Client-Side Testing", ["WSTG-SESS-05"]),
    "CS-02": ("Clickjacking",              "Client-Side Testing", ["WSTG-CLNT-09"]),
    "CS-03": ("CORS Misconfiguration",     "Client-Side Testing", ["WSTG-CLNT-07"]),
    "CS-04": ("Prototype Pollution",       "Client-Side Testing", ["WSTG-CLNT-01"]),
    "CS-05": ("DOM Clobbering",            "Client-Side Testing", ["WSTG-CLNT-01"]),
    "CS-06": ("PostMessage Exploitation",  "Client-Side Testing", ["WSTG-CLNT-11"]),
    "CS-07": ("WebSocket Hijacking (CSWSH)","Client-Side Testing", ["WSTG-CLNT-10"]),
    "CS-08": ("Subdomain Takeover",        "Client-Side Testing", ["WSTG-CONF-10"]),
    "CS-09": ("Tabnabbing / window.opener","Client-Side Testing", ["WSTG-CLNT-14"]),
    "CS-11": ("CSS Exfiltration",          "Client-Side Testing", ["WSTG-CLNT-05"]),
    # Information Disclosure
    "D-01": ("Sensitive File Discovery",   "Information Disclosure", ["WSTG-CONF-04"]),
    "D-02": ("Error Message Mining",       "Information Disclosure", ["WSTG-ERRH-01"]),
    "D-03": ("Source Code Disclosure",     "Information Disclosure", ["WSTG-CONF-04"]),
    "D-04": ("Backup & Archive Finder",    "Information Disclosure", ["WSTG-CONF-04"]),
    "D-05": ("Debug / Admin Panel Finder", "Information Disclosure", ["WSTG-CONF-08"]),
    "D-06": ("API Key / Token in Response","Information Disclosure", ["WSTG-CONF-05"]),
    "D-07": ("Cloud Metadata Exposure",    "Information Disclosure", ["WSTG-CONF-05"]),
    "D-08": ("EXIF / Metadata Extractor",  "Information Disclosure", ["WSTG-INFO-04"]),
    # HTTP Protocol Attacks
    "H-01": ("HTTP Request Smuggling",     "HTTP Protocol Attacks", ["WSTG-INPV-15"]),
    "H-02": ("HTTP Response Splitting",    "HTTP Protocol Attacks", ["WSTG-INPV-15"]),
    "H-03": ("Cache Poisoning",            "HTTP Protocol Attacks", ["WSTG-CONF-12"]),
    "H-04": ("Web Cache Deception",        "HTTP Protocol Attacks", ["WSTG-CONF-12"]),
    "H-05": ("Host Header Injection",      "HTTP Protocol Attacks", ["WSTG-INPV-17"]),
    "H-06": ("HTTP Method Fuzzer",         "HTTP Protocol Attacks", ["WSTG-CONF-06"]),
    "H-07": ("CRLF Injection",             "HTTP Protocol Attacks", ["WSTG-INPV-15"]),
    "H-08": ("Redirect Chain Analysis",    "HTTP Protocol Attacks", ["WSTG-CLNT-04"]),
    # Vulnerability Scanning
    "V-01": ("Nuclei CVE Scan",            "Vulnerability Scanning", []),
    "V-02": ("Nuclei Misconfiguration",    "Vulnerability Scanning", ["WSTG-CONF-01"]),
    "V-03": ("Nuclei Web Templates",       "Vulnerability Scanning", []),
    "V-04": ("Nuclei API Security",        "Vulnerability Scanning", ["WSTG-APIT-01"]),
    "V-05": ("Nuclei Network & Service",   "Vulnerability Scanning", ["WSTG-CONF-06"]),
    "V-06": ("Nuclei Custom YAML",         "Vulnerability Scanning", []),
    "V-07": ("CMS Vulnerability Scanner",  "Vulnerability Scanning", ["WSTG-CONF-01"]),
    "V-08": ("Dependency Vuln Scanner",    "Vulnerability Scanning", []),
    "V-09": ("Default Credentials Tester", "Vulnerability Scanning", ["WSTG-ATHN-02"]),
    "V-10": ("CVE PoC Auto-Matcher",       "Vulnerability Scanning", []),
    # Static / Utilities
    "S-01": ("HTTP Request Analyzer",      "Utilities", []),
    "S-02": ("JWT Decoder & Attacker",     "Utilities", ["WSTG-SESS-10"]),
    "S-03": ("Security Header Auditor",    "Utilities", ["WSTG-CONF-07"]),
    "S-04": ("JS Secret Scanner",          "Utilities", ["WSTG-CONF-05"]),
    "S-05": ("Regex / Payload Lab",        "Utilities", []),
    "S-06": ("Encoding/Decoding Studio",   "Utilities", []),
    "S-07": ("Hash Analyzer",              "Utilities", []),
    "S-08": ("TLS Certificate Inspector",  "Utilities", ["WSTG-CRYP-01"]),
    "S-09": ("HTTP Diff Comparator",       "Utilities", []),
    # Cloud Security
    "C-01": ("S3 Bucket Audit",            "Cloud Security", ["WSTG-CONF-11"]),
    "C-02": ("AWS Metadata Exploit (SSRF)","Cloud Security", ["WSTG-INPV-19"]),
    "C-03": ("Azure Blob Storage Audit",   "Cloud Security", ["WSTG-CONF-11"]),
    "C-04": ("GCP Metadata Service Exploit","Cloud Security", ["WSTG-INPV-19"]),
    "C-05": ("Docker & Kubernetes API",    "Cloud Security", ["WSTG-CONF-01"]),
    "C-06": ("Cloud Asset Discovery",      "Cloud Security", ["WSTG-CONF-11"]),
    "C-07": ("Historical Endpoint Discovery","Cloud Security", ["WSTG-INFO-07"]),
}


# ─── WSTG v4.2 Full Playbook ──────────────────────────────────────────────────
WSTG_PLAYBOOK: list[dict] = [
    {
        "code": "WSTG-INFO", "category": "Information Gathering",
        "tests": [
            {"id": "WSTG-INFO-01", "name": "Conduct Search Engine Discovery Reconnaissance"},
            {"id": "WSTG-INFO-02", "name": "Fingerprint Web Server"},
            {"id": "WSTG-INFO-03", "name": "Review Webserver Metafiles for Information Leakage"},
            {"id": "WSTG-INFO-04", "name": "Enumerate Applications on Webserver"},
            {"id": "WSTG-INFO-05", "name": "Review Webpage Content for Information Leakage"},
            {"id": "WSTG-INFO-06", "name": "Identify Application Entry Points"},
            {"id": "WSTG-INFO-07", "name": "Map Execution Paths Through Application"},
            {"id": "WSTG-INFO-08", "name": "Fingerprint Web Application Framework"},
            {"id": "WSTG-INFO-09", "name": "Fingerprint Web Application"},
            {"id": "WSTG-INFO-10", "name": "Map Application Architecture"},
        ],
    },
    {
        "code": "WSTG-CONF", "category": "Configuration & Deployment Management",
        "tests": [
            {"id": "WSTG-CONF-01", "name": "Test Network Infrastructure Configuration"},
            {"id": "WSTG-CONF-02", "name": "Test Application Platform Configuration"},
            {"id": "WSTG-CONF-03", "name": "Test File Extension Handling for Sensitive Information"},
            {"id": "WSTG-CONF-04", "name": "Review Old Backup and Unreferenced Files"},
            {"id": "WSTG-CONF-05", "name": "Enumerate Infrastructure and Application Admin Interfaces"},
            {"id": "WSTG-CONF-06", "name": "Test HTTP Methods"},
            {"id": "WSTG-CONF-07", "name": "Test HTTP Strict Transport Security"},
            {"id": "WSTG-CONF-08", "name": "Test RIA Cross Domain Policy"},
            {"id": "WSTG-CONF-09", "name": "Test File Permission"},
            {"id": "WSTG-CONF-10", "name": "Test for Subdomain Takeover"},
            {"id": "WSTG-CONF-11", "name": "Test Cloud Storage"},
            {"id": "WSTG-CONF-12", "name": "Test for Content Security Policy"},
        ],
    },
    {
        "code": "WSTG-IDNT", "category": "Identity Management Testing",
        "tests": [
            {"id": "WSTG-IDNT-01", "name": "Test Role Definitions"},
            {"id": "WSTG-IDNT-02", "name": "Test User Registration Process"},
            {"id": "WSTG-IDNT-03", "name": "Test Account Provisioning Process"},
            {"id": "WSTG-IDNT-04", "name": "Testing for Account Enumeration and Guessable User Account"},
            {"id": "WSTG-IDNT-05", "name": "Testing for Weak or Unenforced Username Policy"},
        ],
    },
    {
        "code": "WSTG-ATHN", "category": "Authentication Testing",
        "tests": [
            {"id": "WSTG-ATHN-01", "name": "Testing for Credentials Transported over an Encrypted Channel"},
            {"id": "WSTG-ATHN-02", "name": "Testing for Default Credentials"},
            {"id": "WSTG-ATHN-03", "name": "Testing for Weak Lock Out Mechanism"},
            {"id": "WSTG-ATHN-04", "name": "Testing for Bypassing Authentication Schema"},
            {"id": "WSTG-ATHN-05", "name": "Testing for Vulnerable Remember Password"},
            {"id": "WSTG-ATHN-06", "name": "Testing for Browser Cache Weaknesses"},
            {"id": "WSTG-ATHN-07", "name": "Testing for Weak Password Policy"},
            {"id": "WSTG-ATHN-08", "name": "Testing for Weak Security Question/Answer"},
            {"id": "WSTG-ATHN-09", "name": "Testing for Weak Password Change or Reset Functionalities"},
            {"id": "WSTG-ATHN-10", "name": "Testing for Weaker Authentication in Alternative Channel"},
        ],
    },
    {
        "code": "WSTG-ATHZ", "category": "Authorization Testing",
        "tests": [
            {"id": "WSTG-ATHZ-01", "name": "Testing Directory Traversal / File Include"},
            {"id": "WSTG-ATHZ-02", "name": "Testing for Bypassing Authorization Schema"},
            {"id": "WSTG-ATHZ-03", "name": "Testing for Privilege Escalation"},
            {"id": "WSTG-ATHZ-04", "name": "Testing for Insecure Direct Object References"},
        ],
    },
    {
        "code": "WSTG-SESS", "category": "Session Management Testing",
        "tests": [
            {"id": "WSTG-SESS-01", "name": "Testing for Session Management Schema"},
            {"id": "WSTG-SESS-02", "name": "Testing for Cookies Attributes"},
            {"id": "WSTG-SESS-03", "name": "Testing for Session Fixation"},
            {"id": "WSTG-SESS-04", "name": "Testing for Exposed Session Variables"},
            {"id": "WSTG-SESS-05", "name": "Testing for Cross-Site Request Forgery"},
            {"id": "WSTG-SESS-06", "name": "Testing for Logout Functionality"},
            {"id": "WSTG-SESS-07", "name": "Testing Session Timeout"},
            {"id": "WSTG-SESS-08", "name": "Testing for Session Puzzling"},
            {"id": "WSTG-SESS-09", "name": "Testing for Session Hijacking"},
            {"id": "WSTG-SESS-10", "name": "Testing JSON Web Tokens"},
        ],
    },
    {
        "code": "WSTG-INPV", "category": "Input Validation Testing",
        "tests": [
            {"id": "WSTG-INPV-01", "name": "Testing for Reflected Cross-Site Scripting"},
            {"id": "WSTG-INPV-02", "name": "Testing for Stored Cross-Site Scripting"},
            {"id": "WSTG-INPV-03", "name": "Testing for HTTP Verb Tampering"},
            {"id": "WSTG-INPV-04", "name": "Testing for HTTP Parameter Pollution"},
            {"id": "WSTG-INPV-05", "name": "Testing for SQL Injection"},
            {"id": "WSTG-INPV-06", "name": "Testing for LDAP Injection"},
            {"id": "WSTG-INPV-07", "name": "Testing for XML Injection"},
            {"id": "WSTG-INPV-08", "name": "Testing for SSI Injection"},
            {"id": "WSTG-INPV-09", "name": "Testing for XPath Injection"},
            {"id": "WSTG-INPV-10", "name": "Testing for IMAP/SMTP Injection"},
            {"id": "WSTG-INPV-11", "name": "Testing for Code Injection"},
            {"id": "WSTG-INPV-12", "name": "Testing for Command Injection"},
            {"id": "WSTG-INPV-13", "name": "Testing for Format String / File Upload"},
            {"id": "WSTG-INPV-14", "name": "Testing for Incubated Vulnerability"},
            {"id": "WSTG-INPV-15", "name": "Testing for HTTP Splitting / Smuggling"},
            {"id": "WSTG-INPV-16", "name": "Testing for HTTP Incoming Requests"},
            {"id": "WSTG-INPV-17", "name": "Testing for Host Header Injection"},
            {"id": "WSTG-INPV-18", "name": "Testing for Server-Side Template Injection"},
            {"id": "WSTG-INPV-19", "name": "Testing for Server-Side Request Forgery"},
            {"id": "WSTG-INPV-20", "name": "Testing for Mass Assignment"},
        ],
    },
    {
        "code": "WSTG-ERRH", "category": "Error Handling",
        "tests": [
            {"id": "WSTG-ERRH-01", "name": "Testing for Improper Error Handling"},
            {"id": "WSTG-ERRH-02", "name": "Testing for Stack Traces"},
        ],
    },
    {
        "code": "WSTG-CRYP", "category": "Cryptography",
        "tests": [
            {"id": "WSTG-CRYP-01", "name": "Testing for Weak Transport Layer Security"},
            {"id": "WSTG-CRYP-02", "name": "Testing for Padding Oracle"},
            {"id": "WSTG-CRYP-03", "name": "Testing for Sensitive Information via Unencrypted Channels"},
            {"id": "WSTG-CRYP-04", "name": "Testing for Weak Encryption"},
        ],
    },
    {
        "code": "WSTG-BUSL", "category": "Business Logic Testing",
        "tests": [
            {"id": "WSTG-BUSL-01", "name": "Test Business Logic Data Validation"},
            {"id": "WSTG-BUSL-02", "name": "Test Ability to Forge Requests"},
            {"id": "WSTG-BUSL-03", "name": "Test Integrity Checks"},
            {"id": "WSTG-BUSL-04", "name": "Test for Process Timing"},
            {"id": "WSTG-BUSL-05", "name": "Test Number of Times a Function Can Be Used"},
            {"id": "WSTG-BUSL-06", "name": "Testing for the Circumvention of Work Flows"},
            {"id": "WSTG-BUSL-07", "name": "Test Defenses Against Application Misuse"},
            {"id": "WSTG-BUSL-08", "name": "Test Upload of Unexpected File Types"},
            {"id": "WSTG-BUSL-09", "name": "Test Upload of Malicious Files"},
        ],
    },
    {
        "code": "WSTG-CLNT", "category": "Client-Side Testing",
        "tests": [
            {"id": "WSTG-CLNT-01", "name": "Testing for DOM-Based Cross-Site Scripting"},
            {"id": "WSTG-CLNT-02", "name": "Testing for JavaScript Execution"},
            {"id": "WSTG-CLNT-03", "name": "Testing for HTML Injection"},
            {"id": "WSTG-CLNT-04", "name": "Testing for Client-Side URL Redirect"},
            {"id": "WSTG-CLNT-05", "name": "Testing for CSS Injection"},
            {"id": "WSTG-CLNT-06", "name": "Testing for Client-Side Resource Manipulation"},
            {"id": "WSTG-CLNT-07", "name": "Testing Cross-Origin Resource Sharing"},
            {"id": "WSTG-CLNT-08", "name": "Testing for Cross-Site Flashing"},
            {"id": "WSTG-CLNT-09", "name": "Testing for Clickjacking"},
            {"id": "WSTG-CLNT-10", "name": "Testing WebSockets"},
            {"id": "WSTG-CLNT-11", "name": "Testing Web Messaging"},
            {"id": "WSTG-CLNT-12", "name": "Testing Browser Storage"},
            {"id": "WSTG-CLNT-13", "name": "Testing for Cross-Site Script Inclusion"},
            {"id": "WSTG-CLNT-14", "name": "Testing for Reverse Tabnabbing"},
        ],
    },
    {
        "code": "WSTG-APIT", "category": "API Testing",
        "tests": [
            {"id": "WSTG-APIT-01", "name": "Testing GraphQL"},
            {"id": "WSTG-APIT-02", "name": "Testing REST API"},
        ],
    },
]


# ─── Risk descriptions keyed by severity ──────────────────────────────────────
_RISK_TEXT = {
    "critical": (
        "Immediate exploitation is possible with no privilege requirements. "
        "An attacker can fully compromise the system, execute arbitrary code, or exfiltrate "
        "all sensitive data. Remediation is required immediately.",
        "High",
    ),
    "high": (
        "Significant security risk. An attacker with limited skill can exploit this to gain "
        "unauthorized access, escalate privileges, or cause substantial data loss. "
        "Remediation should be prioritised within 30 days.",
        "High",
    ),
    "medium": (
        "Moderate risk that may lead to limited unauthorized access, data leakage, or "
        "partial system compromise under specific conditions. "
        "Remediation should be planned within 90 days.",
        "Medium",
    ),
    "low": (
        "Limited impact. Exploitation is unlikely to directly compromise the system but "
        "may aid an attacker when combined with other vulnerabilities. "
        "Remediation should be scheduled in the next maintenance cycle.",
        "Low",
    ),
    "info": (
        "Informational finding with no direct exploitation impact. "
        "Represents a deviation from security best practice or minor hardening recommendation.",
        "Low",
    ),
}


# ─── Vulnerability Theoretical Background ────────────────────────────────────
# Maps module_id → concise theoretical background (CWE/OWASP-referenced, authoritative prose)
_VULN_BACKGROUND: dict[str, str] = {
    # Injection
    "I-01": (
        "SQL Injection (CWE-89, OWASP A03:2021 – Injection) is a code injection technique that "
        "exploits the absence of input sanitisation in dynamically constructed database queries. "
        "An adversary who manipulates query structure can bypass authentication, traverse and "
        "exfiltrate the complete database schema, modify or delete records, and—on permissive "
        "server configurations—execute operating-system commands via stored procedures such as "
        "xp_cmdshell (MS-SQL) or LOAD_FILE (MySQL). The root cause is failure to separate code "
        "from data; the canonical remediation is exclusive use of parameterised queries / prepared "
        "statements through the database driver, combined with a least-privilege database account."
    ),
    "I-02": (
        "NoSQL Injection (CWE-943) targets document-oriented stores (MongoDB, CouchDB, Redis) by "
        "injecting operator syntax—$where, $gt, $regex, $elemMatch—into query parameters or JSON "
        "request bodies. Unlike relational SQLi, no SQL knowledge is required; exploitation can "
        "achieve authentication bypass via object injection, mass data exfiltration, and—through "
        "JavaScript evaluation operators—server-side script execution. Remediation relies on "
        "schema validation, driver-level parameter binding, and disabling server-side JS evaluation."
    ),
    "I-03": (
        "LDAP Injection (CWE-90) arises when unvalidated user input is embedded in LDAP filter "
        "strings. Injected metacharacters can alter filter logic to retrieve unauthorised directory "
        "objects, bypass authentication, enumerate user attributes and credentials, and—depending "
        "on LDAP server permissions—modify or delete directory entries. Remediation requires "
        "strict input validation, allowlist filtering of LDAP special characters, and parameterised "
        "LDAP libraries where supported."
    ),
    "I-05": (
        "OS Command Injection (CWE-78, OWASP A03:2021) occurs when an application constructs a "
        "shell command from user-controlled input without adequate sanitisation. An attacker who "
        "appends shell metacharacters (;, &&, |, $(), ``) causes the interpreter to execute "
        "arbitrary operating-system commands in the security context of the web-server process. "
        "Consequences include full host compromise, exfiltration of all accessible files and "
        "credentials, lateral movement across internal networks, and installation of persistent "
        "backdoors. The preferred remediation is to avoid invoking OS shells entirely; where "
        "unavoidable, use allowlist validation and pass arguments through dedicated API calls "
        "rather than string interpolation."
    ),
    "I-06": (
        "Server-Side Template Injection (SSTI, CWE-1336) exploits the evaluation of "
        "attacker-controlled data inside server-side template engines (Jinja2, Twig, Freemarker, "
        "Smarty, Velocity). Template engines expose powerful native objects and functions; an "
        "adversary can traverse the object graph to access the runtime environment, read internal "
        "configuration files and secrets, and ultimately achieve Remote Code Execution. SSTI "
        "frequently arises when developers use templates for user-facing string interpolation "
        "without a dedicated sandbox. Remediation: never render untrusted input as template "
        "source; use context-appropriate output encoding."
    ),
    # XSS
    "X-01": (
        "Reflected Cross-Site Scripting (CWE-79, OWASP A03:2021) arises when user-supplied input "
        "is incorporated into an HTTP response without adequate output encoding. The injected "
        "script executes in the victim's browser under the same-origin trust of the vulnerable "
        "site, enabling session-token theft, credential-form injection, DOM manipulation, and "
        "drive-by malware delivery. Reflected XSS requires social engineering to deliver the "
        "crafted URL. Remediation demands context-sensitive output encoding at every output point "
        "(HTML body, attributes, JavaScript, CSS, URL), combined with a strict Content-Security-Policy."
    ),
    "X-02": (
        "Stored (Persistent) Cross-Site Scripting (CWE-79, OWASP A03:2021) is written to "
        "server-side storage and executed for every user who retrieves the affected resource, "
        "without requiring a malicious link. Compared with Reflected XSS, impact is amplified "
        "because a single injection compromises all subsequent visitors—including administrators. "
        "Exploitation objectives include mass account-takeover, persistent administrative backdoors, "
        "and large-scale phishing campaigns hosted on the trusted domain. Remediation requires "
        "input validation at ingestion and context-sensitive output encoding at every render point."
    ),
    "X-03": (
        "DOM-Based Cross-Site Scripting (CWE-79) occurs entirely within the browser: client-side "
        "JavaScript reads attacker-controlled data from a source (location.hash, document.URL, "
        "window.name, postMessage) and writes it to a dangerous sink (innerHTML, document.write, "
        "eval, setTimeout) without sanitisation. The server-supplied response is never altered, "
        "rendering server-side WAFs and output-encoding controls ineffective. Remediation requires "
        "source-to-sink analysis of all client-side code, use of safe DOM APIs "
        "(textContent, setAttribute), and a strict Content-Security-Policy."
    ),
    # Server-Side Attacks
    "SS-01": (
        "Server-Side Request Forgery (SSRF, CWE-918, OWASP A10:2021) enables an attacker to "
        "cause the server to issue HTTP requests to an attacker-specified destination. Primary "
        "weaponisation targets the cloud instance-metadata endpoint (169.254.169.254 IMDSv1) "
        "to retrieve IAM credentials and user-data secrets, internal services inaccessible from "
        "the internet (databases, admin APIs, key management), and—via Gopher/FTP protocol "
        "switching—protocol-level exploitation. Blind SSRF is confirmed via out-of-band DNS "
        "callbacks (interactsh, Burp Collaborator). Remediation: allowlist permitted URL schemes "
        "and destinations; enforce IMDSv2 (token-based); block metadata ranges at the network layer."
    ),
    "SS-02": (
        "XML External Entity Injection (XXE, CWE-611, OWASP A05:2021 – Security Misconfiguration) "
        "exploits XML parsers that resolve external entity declarations embedded in attacker-controlled "
        "XML. In-band XXE can read arbitrary server files (/etc/passwd, application.properties, "
        "private keys). Blind XXE exfiltrates data via DNS/HTTP out-of-band channels. XXE can also "
        "act as an SSRF vector to probe internal services. Remediation: disable DTD processing and "
        "external entity resolution in the XML parser configuration."
    ),
    "SS-03": (
        "Unrestricted File Upload (CWE-434, OWASP A04:2021 – Insecure Design) occurs when the "
        "application accepts files without validating type, content, or name. Uploading a web shell "
        "(PHP, JSP, ASPX) to a web-accessible directory yields direct Remote Code Execution. Even "
        "non-executable uploads are weaponisable for stored XSS (SVG, HTML), XXE (XML, DOCX), "
        "path traversal, and DoS via decompression bombs. Remediation: validate file type by magic "
        "bytes, reject executable extensions, store uploads outside the web root, and serve them "
        "through a Content-Disposition:attachment response with a randomised filename."
    ),
    "SS-05": (
        "Path Traversal / Local File Inclusion (CWE-22, OWASP A01:2021 – Broken Access Control) "
        "enables an adversary to read files outside the intended directory by manipulating path "
        "parameters with sequences such as ../, ..%2F, or %2e%2e. Disclosed targets include "
        "web-server configuration, application source code, environment files containing credentials, "
        "SSH private keys, and /etc/shadow. On PHP applications that pass user-controlled paths to "
        "require/include, LFI escalates to Remote Code Execution via log poisoning (access.log "
        "injection), PHP filter chain gadgets, or session-file inclusion. Remediation: resolve "
        "canonical paths server-side and enforce strict allowlists for accessible resources."
    ),
    # Authentication
    "AUTH-01": (
        "JSON Web Token vulnerabilities (CWE-345, OWASP A07:2021 – Identification and Authentication "
        "Failures) encompass: acceptance of the 'none' algorithm (no signature verification), "
        "symmetric/asymmetric key confusion (RS256→HS256 downgrade using the public key as HMAC "
        "secret), weak-secret bruteforcing (hashcat -m 16500), improper claims validation "
        "(missing exp, iss, aud checks), and the kid injection vector for SQL/path-traversal. "
        "Successful exploitation yields forged tokens enabling arbitrary privilege escalation "
        "and complete authentication bypass. Remediation: enforce an explicit algorithm allowlist; "
        "verify all standard claims; rotate signing keys; implement token revocation."
    ),
    "AUTH-04": (
        "Credential Brute Force / Weak Lockout (CWE-307, OWASP A07:2021) arises when the "
        "authentication endpoint lacks rate limiting, account lockout, CAPTCHA, or IP-based "
        "throttling. Automated tools can systematically test username/password combinations from "
        "cracked credential dumps, common password lists, or targeted wordlists. The absence of "
        "lockout also enables password-spraying across multiple accounts to avoid per-account "
        "thresholds. Admin-account compromise typically yields full application takeover. "
        "Remediation: implement progressive delays, account lockout with alerting, MFA, and "
        "anomaly-based authentication monitoring."
    ),
    "AUTH-07": (
        "Session Management Weaknesses (CWE-384, CWE-614, OWASP A07:2021) encompass predictable "
        "session identifiers, missing HttpOnly / Secure / SameSite cookie attributes, absence of "
        "session invalidation on logout, indefinite session lifetimes, and session fixation vectors. "
        "Exploitation enables persistent account takeover even after a victim changes their password. "
        "Remediation requires cryptographically random tokens (≥128 bits), strict cookie attributes, "
        "server-side session invalidation on logout, and absolute/idle timeout enforcement."
    ),
    "AUTH-08": (
        "Password Reset Vulnerabilities (CWE-640, OWASP A07:2021) include predictable reset tokens, "
        "tokens with excessive validity windows, Host-header injection into reset-link generation "
        "(allowing token exfiltration to an attacker-controlled server), absence of token "
        "single-use enforcement, and lack of old-password re-authentication. Exploitation enables "
        "account takeover without knowing the current credential. Remediation: use cryptographically "
        "random tokens with short TTL (≤15 min), enforce single-use consumption, validate the Host "
        "header against an allowlist."
    ),
    # Access Control
    "AC-01": (
        "Insecure Direct Object Reference / Broken Object-Level Authorisation (IDOR / BOLA, "
        "CWE-639, OWASP A01:2021 – Broken Access Control) exists when the server exposes internal "
        "identifiers (database PKs, file paths, sequential IDs) in API parameters and fails to "
        "verify the requesting principal's entitlement to the referenced object. An attacker "
        "enumerates or predicts identifiers to access, modify, or delete other users' records—"
        "including payment data, personal information, and account credentials—without requiring "
        "elevated privileges. Remediation: enforce object-level authorisation checks server-side "
        "for every request; prefer non-guessable indirect references (UUIDs, HMAC-signed tokens)."
    ),
    "AC-03": (
        "Privilege Escalation (CWE-269, OWASP A01:2021) occurs when server-side authorisation "
        "logic is absent or incomplete, permitting a lower-privileged principal to assume "
        "capabilities reserved for a higher-privileged role. Vertical escalation grants "
        "administrative functions; horizontal escalation grants access to peer-user resources. "
        "Common attack vectors include mass assignment of privileged attributes, JWT role "
        "manipulation, HTTP parameter tampering, and predictable role identifiers. Remediation: "
        "centralise authorisation logic using a deny-by-default model; validate role assignments "
        "exclusively on the server; apply the principle of least privilege."
    ),
    # Business Logic
    "BL-01": (
        "Race Conditions in Web Applications (CWE-362 – Concurrent Execution, OWASP A04:2021) "
        "arise when two or more concurrent requests share mutable state without adequate "
        "synchronisation. In the TOCTOU (Time-Of-Check to Time-Of-Use) pattern, an attacker who "
        "wins the race can bypass single-use constraints (coupon codes, referral bonuses), deplete "
        "shared resources beyond permitted limits, or consume transient authentication tokens "
        "(2FA codes) multiple times. Exploitation typically requires sending parallel requests at "
        "sub-millisecond granularity. Remediation: use atomic database operations (SELECT … FOR "
        "UPDATE), idempotency tokens, distributed locks, or optimistic concurrency control."
    ),
    # API
    "API-01": (
        "REST API vulnerabilities (OWASP API Security Top-10) encompass broken object-level "
        "authorisation (BOLA/IDOR), excessive data exposure, mass assignment, missing function-level "
        "access control, lack of rate limiting, improper asset management (shadow APIs, deprecated "
        "endpoints), and injection through unsanitised query/body parameters. APIs present a "
        "distinct attack surface from traditional web UIs; security controls must be independently "
        "assessed and not assumed to mirror the front-end application."
    ),
    "API-03": (
        "Mass Assignment (CWE-915, OWASP A03:2021 / API6:2023) occurs when an API framework "
        "automatically binds all request-body properties to internal object fields without "
        "explicitly allowlisting user-settable attributes. An attacker can inject privileged fields "
        "not intended for user modification—such as is_admin, role, account_balance, or "
        "email_verified—achieving privilege escalation or account manipulation in a single "
        "request. Remediation: define explicit input DTOs / serialiser field whitelists; never "
        "expose internal model fields without an explicit mapping layer."
    ),
    "API-06": (
        "GraphQL Security vulnerabilities include introspection abuse (full schema enumeration via "
        "__schema), batching-based rate-limit bypass (sending thousands of operations in one "
        "request), deeply nested query DoS (N+1 resolver exhaustion), missing field-level "
        "authorisation (fields accessible only via GraphQL that are blocked on the REST API), "
        "unsanitised resolver variables enabling injection, and subscription abuse. GraphQL's "
        "flexible query model significantly expands the attack surface compared to REST. "
        "Remediation: disable introspection in production; implement query depth/complexity limits "
        "and per-operation rate limiting; enforce authorisation at the resolver level."
    ),
    # Client-Side
    "CS-01": (
        "Cross-Site Request Forgery (CSRF, CWE-352, OWASP A01:2021) exploits the browser's "
        "automatic inclusion of session cookies in cross-origin requests. A malicious page "
        "crafted by the attacker causes an authenticated victim's browser to perform "
        "state-changing actions—password/email changes, fund transfers, privilege grants—on the "
        "target application, entirely without the victim's knowledge or consent. Modern mitigations "
        "include the SameSite=Strict/Lax cookie attribute, server-side CSRF tokens (Synchroniser "
        "Token Pattern), and the Double-Submit Cookie pattern."
    ),
    "CS-03": (
        "CORS Misconfiguration (CWE-942) arises when the Access-Control-Allow-Origin response "
        "header reflects arbitrary request origins or is set to wildcard (*) in conjunction with "
        "credentials. A malicious cross-origin page can issue credentialed XHR/Fetch requests to "
        "the vulnerable API and read the full response, enabling exfiltration of session tokens, "
        "PII, API keys, and user account data—all without any victim interaction beyond visiting "
        "the attacker's site. Remediation: maintain an explicit origin allowlist; never pair "
        "Access-Control-Allow-Credentials: true with a wildcard or reflected origin."
    ),
    # Information Disclosure
    "D-01": (
        "Sensitive File Exposure (CWE-538 / CWE-219, OWASP A05:2021) results from web-server or "
        "application misconfiguration that makes configuration files, backup archives, source code, "
        "or environment files (.env, .git, web.config) directly retrievable by unauthenticated "
        "users. Disclosed artefacts frequently contain database credentials, API keys, encryption "
        "secrets, internal network topology, and application business logic that substantially "
        "accelerate exploitation of secondary vulnerabilities. Remediation: restrict web-accessible "
        "paths to only required resources; enforce server-side access controls; remove backup and "
        "debug artefacts from production."
    ),
    "D-02": (
        "Verbose Error Messages (CWE-209, OWASP A05:2021 – Security Misconfiguration) disclose "
        "implementation details—stack traces, database schema, framework/version strings, internal "
        "file system paths, and environment variables—that provide high-value reconnaissance to an "
        "adversary. Technologies can be fingerprinted precisely; disclosed paths accelerate "
        "directory traversal and LFI attacks; exposed credentials in tracebacks enable immediate "
        "compromise. Production systems must present only generic, non-disclosing error messages "
        "to clients while logging full detail server-side in a secured audit log."
    ),
    # HTTP Protocol Attacks
    "H-01": (
        "HTTP Request Smuggling (CWE-444, OWASP A05:2021) exploits discrepancies between how a "
        "front-end proxy and a back-end server parse ambiguous Transfer-Encoding / Content-Length "
        "headers. The attacker crafts a request whose body is interpreted as the beginning of a "
        "subsequent request by the back-end, allowing them to: prepend arbitrary content to "
        "subsequent users' requests (account takeover), bypass security controls enforced at the "
        "edge (WAF, authentication middleware), and exfiltrate other users' request headers. "
        "Remediation: normalise HTTP/1.1 ambiguous requests at the edge; prefer HTTP/2 end-to-end "
        "(immune by design); disable HTTP reuse between proxy and origin."
    ),
    "H-05": (
        "Host Header Injection (CWE-20, OWASP A03:2021) arises when the application trusts the "
        "HTTP Host header for security-sensitive operations—generating absolute URLs in password "
        "reset emails, constructing OAuth redirect URIs, or routing SSRF callbacks—without "
        "validating it against a server-side allowlist. An attacker who controls this header can "
        "redirect reset-link tokens to an attacker-controlled host, poison application-level "
        "caches with injected URLs, or probe internal services via crafted Host values. "
        "Remediation: configure a hard-coded allowlist of valid hostnames server-side; never "
        "derive security-sensitive URLs from the Host header."
    ),
    # Reconnaissance / Config
    "R-03": (
        "TLS/SSL Misconfiguration (CWE-326 – Inadequate Encryption Strength, OWASP A02:2021 – "
        "Cryptographic Failures) encompasses the use of deprecated protocol versions (SSLv3, "
        "TLS 1.0, TLS 1.1), weak cipher suites (RC4, 3DES/SWEET32, NULL, EXPORT), missing "
        "Perfect Forward Secrecy (non-ECDHE key exchange), self-signed or expired certificates, "
        "absence of HSTS, and insecure renegotiation. These weaknesses expose in-transit data to "
        "passive interception and active downgrade attacks (BEAST, POODLE, DROWN, CRIME/BREACH). "
        "Remediation: enforce TLS 1.2+ with PFS cipher suites; deploy HSTS with a long max-age "
        "and the includeSubDomains directive; renew certificates before expiry."
    ),
    "S-03": (
        "Missing or Misconfigured Security Headers (CWE-693, OWASP A05:2021) expose the "
        "application to a range of client-side attacks. The Content-Security-Policy header "
        "prevents XSS and data-injection; Strict-Transport-Security enforces HTTPS; "
        "X-Frame-Options / CSP frame-ancestors prevent clickjacking; X-Content-Type-Options "
        "prevents MIME-type sniffing; Referrer-Policy controls information leakage in Referer "
        "headers; Permissions-Policy restricts browser feature access. The absence of these "
        "controls does not introduce direct vulnerabilities but significantly degrades defence-in-depth "
        "and enables exploitation of secondary weaknesses."
    ),
    # Cloud
    "C-01": (
        "S3 Bucket Misconfiguration (CWE-732 – Incorrect Permission Assignment, OWASP A01:2021) "
        "results from overly permissive ACLs or bucket policies that grant public ListBucket, "
        "GetObject, or PutObject access to the AllUsers / AuthenticatedUsers principals. "
        "Publicly readable buckets may disclose PII, credentials, application backups, and "
        "proprietary source code. Publicly writable buckets enable content injection (XSS via "
        "hosted JS), malware staging, and supply-chain attacks. Remediation: enforce 'Block "
        "Public Access' at the account level; apply least-privilege bucket policies; enable "
        "S3 Access Logging and GuardDuty S3 data-event monitoring."
    ),
}


# ─── CVSS helpers ─────────────────────────────────────────────────────────────

def _cvss_label(score) -> tuple[str, str]:
    """Return (qualitative_label, css_class) for a CVSS v3.1 numeric score."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ("N/A", "cvss-na")
    if s == 0.0:
        return ("None", "cvss-none")
    if s < 4.0:
        return ("Low", "cvss-low")
    if s < 7.0:
        return ("Medium", "cvss-med")
    if s < 9.0:
        return ("High", "cvss-high")
    return ("Critical", "cvss-crit")


def _cvss_nvd_url(vector: str) -> str:
    """NVD CVSS v3.1 calculator URL for a vector string."""
    if not vector:
        return ""
    from urllib.parse import quote
    return f"https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector={quote(vector)}&version=3.1"


def _cve_nvd_url(cve_id: str) -> str:
    """NVD CVE detail page URL."""
    if not cve_id:
        return ""
    cid = cve_id.upper().strip()
    if not cid.startswith("CVE-"):
        return ""
    return f"https://nvd.nist.gov/vuln/detail/{cid}"


# ─── FindingWrapper ────────────────────────────────────────────────────────────

class FindingWrapper:
    """Wraps a Finding model instance and augments it with computed report fields.

    All original model attributes are transparently proxied via __getattr__,
    so templates can use ``{{ f.title }}``, ``{{ f.severity }}``, etc. unchanged,
    while also accessing ``{{ f.cvss_label }}``, ``{{ f.cve_nvd_url }}``, etc.
    """

    def __init__(self, finding, seq_num: int) -> None:
        self._f = finding
        self.num = seq_num

        # CVSS v3.1
        self.cvss_label, self.cvss_class = _cvss_label(finding.cvss_score)
        self.cvss_nvd_url = _cvss_nvd_url(getattr(finding, "cvss_vector", "") or "")
        self.cve_nvd_url  = _cve_nvd_url(getattr(finding, "cve_id", "") or "")

        # Module info from registry
        mid = ""
        if finding.scan_job:
            mid = getattr(finding.scan_job, "module_id", "") or ""
        info = MODULE_REGISTRY.get(mid, (mid, "", []))
        self.module_name = info[0]
        self.module_cat  = info[1]
        self.wstg_refs   = info[2]

        # Risk text
        risk_info = _RISK_TEXT.get(finding.severity, _RISK_TEXT["info"])
        self.risk_text  = risk_info[0]
        self.likelihood = risk_info[1]

        # Theoretical background (keyed by module_id; empty string = no background defined)
        self.background = _VULN_BACKGROUND.get(mid, "")

    def __getattr__(self, name: str):
        return getattr(self._f, name)

    def get_status_display(self) -> str:
        return self._f.get_status_display() if hasattr(self._f, "get_status_display") else self._f.status


# ─── Data helpers ─────────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MIN_SEV_FILTER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _get_findings(report: "Report"):
    """Return ordered Finding queryset respecting report.finding_ids, targets, min_severity."""
    from apps.results.models import Finding

    min_rank = _MIN_SEV_FILTER.get(report.min_severity, 4)
    target_ids = list(report.targets.values_list("pk", flat=True)) if report.pk else []

    if report.finding_ids:
        id_order = {str(fid): idx for idx, fid in enumerate(report.finding_ids)}
        qs = Finding.objects.filter(
            pk__in=report.finding_ids,
            status__in=["open", "confirmed", "mitigated"],
        ).select_related("scan_job")
        if target_ids:
            qs = qs.filter(
                models.Q(scan_job__target_id__in=target_ids) | models.Q(scan_job__isnull=True)
            )
        result = [f for f in qs if _SEVERITY_ORDER.get(f.severity, 4) <= min_rank]
        result.sort(key=lambda f: id_order.get(str(f.pk), 9999))
        return result
    else:
        from django.db.models import Q as DQ
        qs = Finding.objects.filter(
            DQ(project=report.project) | DQ(project__isnull=True, scan_job__project=report.project),
            status__in=["open", "confirmed", "mitigated"],
        ).select_related("scan_job").order_by("severity", "-created_at")
        if target_ids:
            qs = qs.filter(
                DQ(scan_job__target_id__in=target_ids) | DQ(scan_job__isnull=True)
            )
        return [f for f in qs if _SEVERITY_ORDER.get(f.severity, 4) <= min_rank]


def _count_by_severity(findings) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = getattr(f, "severity", None) or "info"
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _get_methodology(report: "Report") -> list[dict]:
    """Return unique modules executed for this project's scan jobs, ordered by category."""
    try:
        from apps.scans.models import ScanJob
    except ImportError:
        return []

    jobs = (
        ScanJob.objects.filter(project=report.project)
        .select_related("target")
        .order_by("module_id", "-created_at")
    )
    seen: set[str] = set()
    methodology: list[dict] = []
    for job in jobs:
        mid = job.module_id or ""
        if mid in seen:
            continue
        seen.add(mid)
        info = MODULE_REGISTRY.get(mid, (mid, "Other", []))
        methodology.append({
            "module_id":   mid,
            "name":        info[0],
            "category":    info[1],
            "wstg_refs":   info[2],
            "status":      job.status,
            "started_at":  job.started_at,
            "finished_at": getattr(job, "finished_at", None),
            "target":      str(job.target) if job.target else "",
        })
    methodology.sort(key=lambda m: (m["category"], m["module_id"]))
    return methodology


def _get_sow_targets(report: "Report") -> list:
    """Return Target objects associated with this report."""
    try:
        from apps.targets.models import Target
    except ImportError:
        return []

    target_ids = list(report.targets.values_list("pk", flat=True)) if report.pk else []
    if target_ids:
        qs = Target.objects.filter(pk__in=target_ids)
    else:
        qs = Target.objects.filter(project=report.project)
    return list(qs.order_by("target_type", "value"))


def _build_wstg_with_coverage(methodology: list[dict]) -> list[dict]:
    """Annotate every WSTG test with a covered flag based on executed modules."""
    covered: set[str] = set()
    for m in methodology:
        for ref in m.get("wstg_refs", []):
            covered.add(ref)

    result = []
    for cat in WSTG_PLAYBOOK:
        tests_annotated = [
            {"id": t["id"], "name": t["name"], "covered": t["id"] in covered}
            for t in cat["tests"]
        ]
        result.append({
            "code":          cat["code"],
            "category":      cat["category"],
            "tests":         tests_annotated,
            "covered_count": sum(1 for t in tests_annotated if t["covered"]),
            "total_count":   len(tests_annotated),
        })
    return result


# ─── Generators ───────────────────────────────────────────────────────────────

def generate_json(report: "Report") -> bytes:
    """Return JSON bytes of the full professional report."""
    findings_raw = _get_findings(report)
    findings     = [FindingWrapper(f, i + 1) for i, f in enumerate(findings_raw)]
    counts       = _count_by_severity(findings_raw)
    methodology  = _get_methodology(report)
    targets      = _get_sow_targets(report)
    wstg         = _build_wstg_with_coverage(methodology)

    def _f_to_dict(f: FindingWrapper) -> dict:
        return {
            "num":         f.num,
            "title":       f.title,
            "severity":    f.severity,
            "url":         f.url or "",
            "status":      f.status,
            "status_display": f.get_status_display(),
            "description": f.description or "",
            "evidence":    f.evidence or "" if report.include_evidence else "",
            "remediation": f.remediation or "" if report.include_remediation else "",
            "cvss_score":  str(f.cvss_score) if f.cvss_score is not None else "",
            "cvss_label":  f.cvss_label,
            "cvss_vector": f.cvss_vector or "",
            "cvss_nvd_url": f.cvss_nvd_url,
            "cve_id":      f.cve_id or "",
            "cve_nvd_url": f.cve_nvd_url,
            "cwe_id":      f.cwe_id or "",
            "module_id":   f._f.scan_job.module_id if f._f.scan_job else "",
            "module_name": f.module_name,
            "module_cat":  f.module_cat,
            "wstg_refs":   f.wstg_refs,
            "risk_text":   f.risk_text,
            "likelihood":  f.likelihood,
        }

    payload = {
        "report": {
            "id":               str(report.pk),
            "title":            report.title,
            "company_name":     report.company_name or "",
            "assessor_name":    report.assessor_name or "",
            "report_date":      report.report_date.isoformat() if report.report_date else "",
            "engagement_type":  getattr(report, "engagement_type", "black-box"),
            "executive_summary": report.executive_summary or "",
            "methodology_notes": getattr(report, "methodology_notes", ""),
            "scope_notes":       getattr(report, "scope_notes", ""),
        },
        "severity_counts": counts,
        "total_findings":  len(findings),
        "scope_of_work": [
            {
                "name":        t.name,
                "target_type": t.target_type,
                "value":       t.value,
                "is_in_scope": t.is_in_scope,
                "description": t.description or "",
            }
            for t in targets
        ],
        "methodology": methodology,
        "wstg_coverage": [
            {
                "code":          c["code"],
                "category":      c["category"],
                "covered_count": c["covered_count"],
                "total_count":   c["total_count"],
            }
            for c in wstg
        ],
        "findings": [_f_to_dict(f) for f in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


def generate_markdown(report: "Report") -> str:
    """Render full Markdown report with all professional sections."""
    findings_raw = _get_findings(report)
    findings     = [FindingWrapper(f, i + 1) for i, f in enumerate(findings_raw)]
    counts       = _count_by_severity(findings_raw)
    methodology  = _get_methodology(report)
    targets      = _get_sow_targets(report)
    wstg         = _build_wstg_with_coverage(methodology)
    today        = report.report_date.isoformat() if report.report_date else date.today().isoformat()

    lines: list[str] = []
    a = lines.append

    # Cover
    a(f"# {report.title}")
    a("**Web Application Penetration Test Report**\n")
    a(f"| Field | Value |")
    a(f"|---|---|")
    a(f"| Project | {report.project} |")
    if report.company_name:
        a(f"| Client | {report.company_name} |")
    if report.assessor_name:
        a(f"| Assessor | {report.assessor_name} |")
    a(f"| Date | {today} |")
    a(f"| Engagement | {getattr(report, 'engagement_type', 'black-box').capitalize()} |")
    a(f"| Total Findings | {len(findings)} |")
    a("\n> **CONFIDENTIAL** — This document contains sensitive security information.\n")

    # 1. Executive Summary
    a("---\n## 1. Executive Summary\n")
    a(f"| Severity | Count |")
    a(f"|---|---|")
    for sev in ("critical", "high", "medium", "low", "info"):
        a(f"| {sev.capitalize()} | {counts.get(sev, 0)} |")
    a("")
    if report.executive_summary:
        a(f"{report.executive_summary}\n")

    # 2. Testing Methodology
    a("---\n## 2. Testing Methodology\n")
    a(f"**Engagement Type:** {getattr(report, 'engagement_type', 'black-box').capitalize()}\n")
    mn = getattr(report, "methodology_notes", "")
    if mn:
        a(f"{mn}\n")
    if methodology:
        a("| Module ID | Name | Category | WSTG Refs | Status |")
        a("|---|---|---|---|---|")
        for m in methodology:
            refs = ", ".join(m["wstg_refs"]) or "—"
            a(f"| {m['module_id']} | {m['name']} | {m['category']} | {refs} | {m['status']} |")
    a("")

    # 3. Scope of Work
    a("---\n## 3. Scope of Work\n")
    sn = getattr(report, "scope_notes", "")
    if sn:
        a(f"{sn}\n")
    if targets:
        a("| # | Name | Type | Value | In-Scope | Description |")
        a("|---|---|---|---|---|---|")
        for i, t in enumerate(targets, 1):
            in_scope = "Yes" if t.is_in_scope else "No"
            a(f"| {i} | {t.name} | {t.target_type} | {t.value} | {in_scope} | {t.description or ''} |")
    a("")

    # 4. Findings Summary
    a("---\n## 4. Findings Summary\n")
    if findings:
        a("| # | Title | Severity | URL | CVSS | CVE | Status |")
        a("|---|---|---|---|---|---|---|")
        for f in findings:
            cvss = f"{f.cvss_score} ({f.cvss_label})" if f.cvss_score else "—"
            cve  = f.cve_id or "—"
            url  = (f.url or "")[:60]
            a(f"| {f.num} | {f.title} | {f.severity.upper()} | {url} | {cvss} | {cve} | {f.get_status_display()} |")
    a("")

    # 5. Detailed Findings
    a("---\n## 5. Detailed Findings\n")
    for f in findings:
        a(f"### Finding #{f.num}: {f.title}")
        a(f"**Severity:** {f.severity.upper()} · **Status:** {f.get_status_display()}")
        if f.cvss_score:
            nvd = f" ([NVD]({f.cvss_nvd_url}))" if f.cvss_nvd_url else ""
            a(f"**CVSS v3.1:** {f.cvss_score} — {f.cvss_label}{nvd}")
        if f.cvss_vector:
            a(f"**CVSS Vector:** `{f.cvss_vector}`")
        if f.cve_id:
            nvd2 = f" ([NVD]({f.cve_nvd_url}))" if f.cve_nvd_url else ""
            a(f"**CVE:** {f.cve_id}{nvd2}")
        if f.cwe_id:
            a(f"**CWE:** {f.cwe_id}")
        if f.url:
            a(f"**URL:** `{f.url}`")
        if f.wstg_refs:
            a(f"**WSTG:** {', '.join(f.wstg_refs)}")
        a(f"**Risk:** {f.risk_text}")
        if f.description:
            a(f"\n**Description**\n\n{f.description}")
        if f.evidence and report.include_evidence:
            a(f"\n**Evidence / PoC**\n\n```\n{f.evidence[:2000]}\n```")
        if f.remediation and report.include_remediation:
            a(f"\n**Recommendation**\n\n{f.remediation}")
        a("")

    # 6. WSTG Playbook
    a("---\n## 6. WSTG v4.2 Testing Playbook\n")
    for cat in wstg:
        a(f"### {cat['code']} — {cat['category']}  ({cat['covered_count']}/{cat['total_count']} covered)\n")
        a("| Test ID | Test Name | Coverage |")
        a("|---|---|---|")
        for t in cat["tests"]:
            cov = "✓ Covered" if t["covered"] else "— Not tested"
            a(f"| `{t['id']}` | {t['name']} | {cov} |")
        a("")

    return "\n".join(lines)


def generate_html(report: "Report") -> str:
    """Render full standalone HTML report using Django template engine."""
    from django.template.loader import render_to_string

    findings_raw = _get_findings(report)
    findings     = [FindingWrapper(f, i + 1) for i, f in enumerate(findings_raw)]
    counts       = _count_by_severity(findings_raw)
    methodology  = _get_methodology(report)
    targets      = _get_sow_targets(report)
    wstg         = _build_wstg_with_coverage(methodology)
    risk_matrix  = build_risk_matrix(report)
    today        = report.report_date.isoformat() if report.report_date else date.today().isoformat()

    max_count = max(counts.values()) if any(counts.values()) else 1
    severity_bars = [
        {
            "sev": sev,
            "cnt": counts.get(sev, 0),
            "pct": int(counts.get(sev, 0) / max_count * 100),
        }
        for sev in ("critical", "high", "medium", "low", "info")
    ]

    context = {
        "report":            report,
        "findings":          findings,
        "counts":            counts,
        "today":             today,
        "total":             len(findings),
        "severity_bars":     severity_bars,
        "methodology":       methodology,
        "targets":           targets,
        "wstg_playbook":     wstg,
        "risk_matrix":       risk_matrix,
        "engagement_type":   getattr(report, "engagement_type", "black-box"),
        "methodology_notes": getattr(report, "methodology_notes", ""),
        "scope_notes":       getattr(report, "scope_notes", ""),
    }
    return render_to_string("reports/export_html.html", context)


def generate_pdf(report: "Report") -> bytes:
    """Render HTML report and convert to PDF via WeasyPrint."""
    try:
        from weasyprint import HTML, CSS
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("WeasyPrint is not installed") from exc

    html_content = generate_html(report)
    return HTML(string=html_content, base_url=None).write_pdf()


def build_risk_matrix(report: "Report") -> dict:
    """Return a dict usable as a risk-matrix data structure for the report template."""
    findings = _get_findings(report)

    IMPACT_MAP    = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    LIKELIHOOD_MAP = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

    matrix: dict[str, dict[str, list]] = {}
    for f in findings:
        impact     = IMPACT_MAP.get(f.severity, 1)
        likelihood = LIKELIHOOD_MAP.get(f.severity, 1)
        cell       = f"{impact},{likelihood}"
        matrix.setdefault(cell, []).append({"title": f.title, "severity": f.severity})

    return {
        "cells":    matrix,
        "severity_counts": _count_by_severity(findings),
    }
