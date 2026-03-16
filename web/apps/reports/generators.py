"""
Report export generators — HTML, PDF (WeasyPrint), JSON, Markdown.
Called from Celery tasks or directly from views for small reports.
"""
from __future__ import annotations
import json
import io
import textwrap
from datetime import date
from typing import TYPE_CHECKING
from django.db import models

if TYPE_CHECKING:
    from apps.reports.models import Report


# ─── Helpers ──────────────────────────────────────────────────────────────────

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MIN_SEV_FILTER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _get_findings(report: "Report"):
    """Return ordered Finding queryset respecting report.finding_ids, targets, and min_severity."""
    from apps.results.models import Finding

    min_rank = _MIN_SEV_FILTER.get(report.min_severity, 4)

    # Determine target filter
    target_ids = list(report.targets.values_list("pk", flat=True)) if report.pk else []

    if report.finding_ids:
        # Preserve user-defined order
        id_order = {str(fid): idx for idx, fid in enumerate(report.finding_ids)}
        qs = Finding.objects.filter(
            pk__in=report.finding_ids,
            status__in=["open", "confirmed", "mitigated"],
        )
        if target_ids:
            qs = qs.filter(
                models.Q(scan_job__target_id__in=target_ids) |
                models.Q(scan_job__isnull=True)
            )
        qs = [f for f in qs if _SEVERITY_ORDER.get(f.severity, 4) <= min_rank]
        qs.sort(key=lambda f: id_order.get(str(f.pk), 9999))
        return qs
    else:
        # Include findings linked directly to the project OR linked via scan_job
        # (handles legacy findings created before bulk_create project-FK fix).
        from django.db.models import Q as DQ
        qs = Finding.objects.filter(
            DQ(project=report.project) |
            DQ(project__isnull=True, scan_job__project=report.project),
            status__in=["open", "confirmed", "mitigated"],
        ).order_by("severity", "-created_at")
        if target_ids:
            qs = qs.filter(
                DQ(scan_job__target_id__in=target_ids) |
                DQ(scan_job__isnull=True)
            )
        return [f for f in qs if _SEVERITY_ORDER.get(f.severity, 4) <= min_rank]


def _count_by_severity(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


# ─── JSON Export ──────────────────────────────────────────────────────────────

def generate_json(report: "Report") -> bytes:
    """Return UTF-8 encoded JSON report."""
    findings = _get_findings(report)
    counts = _count_by_severity(findings)

    data = {
        "report": {
            "title": report.title,
            "project": str(report.project),
            "company": report.company_name,
            "assessor": report.assessor_name,
            "date": report.report_date.isoformat() if report.report_date else date.today().isoformat(),
            "executive_summary": report.executive_summary,
            "summary": counts,
            "total_findings": len(findings),
        },
        "findings": [
            {
                "id": str(f.pk),
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "url": f.url,
                "description": f.description,
                "evidence": f.evidence if report.include_evidence else "",
                "remediation": f.remediation if report.include_remediation else "",
                "cvss_score": str(f.cvss_score) if f.cvss_score else None,
                "cvss_vector": f.cvss_vector,
                "cve_id": f.cve_id,
                "cwe_id": f.cwe_id,
                "created_at": f.created_at.isoformat(),
            }
            for f in findings
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")


# ─── Markdown Export ──────────────────────────────────────────────────────────

def generate_markdown(report: "Report") -> str:
    """Return Markdown-formatted report suitable for GitLab/GitHub issues."""
    findings = _get_findings(report)
    counts = _count_by_severity(findings)
    today = report.report_date.isoformat() if report.report_date else date.today().isoformat()

    sev_icon = {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"
    }

    lines = [
        f"# {report.title}",
        "",
        f"**Project:** {report.project}  ",
        f"**Date:** {today}  ",
        f"**Assessor:** {report.assessor_name or 'N/A'}  ",
        f"**Company:** {report.company_name or 'N/A'}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        report.executive_summary or "_No executive summary provided._",
        "",
        "---",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        icon = sev_icon.get(sev, "")
        lines.append(f"| {icon} {sev.capitalize()} | {counts.get(sev, 0)} |")

    lines += ["", "---", "", "## Findings", ""]

    for idx, f in enumerate(findings, 1):
        icon = sev_icon.get(f.severity, "")
        lines += [
            f"### {idx}. {icon} {f.title}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Severity** | `{f.severity.upper()}` |",
            f"| **Status** | `{f.status}` |",
            f"| **URL** | `{f.url}` |",
            f"| **CWE** | {f.cwe_id or 'N/A'} |",
            f"| **CVE** | {f.cve_id or 'N/A'} |",
            f"| **CVSS** | {f.cvss_score or 'N/A'} |",
            "",
            "**Description**",
            "",
            f.description or "_No description._",
            "",
        ]
        if report.include_evidence and f.evidence:
            lines += [
                "**Evidence**",
                "",
                "```",
                f.evidence[:2000],
                "```",
                "",
            ]
        if report.include_remediation and f.remediation:
            lines += [
                "**Remediation**",
                "",
                f.remediation,
                "",
            ]
        lines += ["---", ""]

    return "\n".join(lines)


# ─── HTML Report ──────────────────────────────────────────────────────────────

def generate_html(report: "Report") -> str:
    """Render full standalone HTML report using Django template engine."""
    from django.template.loader import render_to_string
    findings = _get_findings(report)
    counts = _count_by_severity(findings)
    today = report.report_date.isoformat() if report.report_date else date.today().isoformat()

    context = {
        "report": report,
        "findings": findings,
        "counts": counts,
        "today": today,
        "total": len(findings),
    }
    return render_to_string("reports/export_html.html", context)


# ─── PDF Report ───────────────────────────────────────────────────────────────

def generate_pdf(report: "Report") -> bytes:
    """
    Convert HTML report → PDF bytes via WeasyPrint.
    Returns raw PDF bytes.
    """
    from weasyprint import HTML as WeasyHTML, CSS
    html_content = generate_html(report)
    pdf_bytes = WeasyHTML(
        string=html_content,
        base_url=None,
    ).write_pdf()
    return pdf_bytes


# ─── Risk Matrix Data ─────────────────────────────────────────────────────────

def build_risk_matrix(report: "Report") -> dict:
    """
    Build 5×5 risk heatmap data.
    Returns dict with cells keyed by (severity, likelihood) with finding counts.
    """
    findings = _get_findings(report)
    # Severity → row index (0=critical, 4=info)
    sev_row = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    # We approximate likelihood from severity (no explicit likelihood field yet)
    sev_likelihood = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    # 5x5 matrix: rows = impact (bottom=low, top=critical), cols = likelihood
    matrix = [[0] * 5 for _ in range(5)]
    for f in findings:
        r = sev_row.get(f.severity, 0)
        c = sev_likelihood.get(f.severity, 0)
        matrix[r][c] += 1

    return {
        "matrix": matrix,
        "rows": ["Info", "Low", "Medium", "High", "Critical"],
        "cols": ["Rare", "Unlikely", "Possible", "Likely", "Certain"],
    }
