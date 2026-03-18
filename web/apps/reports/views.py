"""
Reports views — create, builder, generate, download, risk matrix.
"""
from __future__ import annotations
import os
import json
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render, redirect
from django.http import HttpResponse, JsonResponse, FileResponse, Http404
from django.views.decorators.http import require_POST, require_http_methods
from django.contrib import messages
from django.db.models import Q
from django.utils import timezone

from .models import Report


def _user_report(user, report_id):
    report = get_object_or_404(Report, pk=report_id)
    if user.is_superuser:
        return report
    if report.project.owner == user or report.project.members.filter(pk=user.pk).exists():
        return report
    from django.core.exceptions import PermissionDenied
    raise PermissionDenied


# ─── Report list ─────────────────────────────────────────────────────────────

@login_required
def report_list(request):
    from apps.targets.models import Project

    projects = Project.objects.filter(
        Q(owner=request.user) | Q(members=request.user)
    ).distinct()

    reports = Report.objects.filter(project__in=projects).select_related("project", "created_by")

    return render(request, "reports/list.html", {"reports": reports, "projects": projects})


# ─── Create ───────────────────────────────────────────────────────────────────

@login_required
@require_http_methods(["GET", "POST"])
def report_create(request):
    from apps.targets.models import Project

    projects = Project.objects.filter(
        Q(owner=request.user) | Q(members=request.user)
    ).distinct().prefetch_related("targets")

    if request.method == "POST":
        data = request.POST
        project_id = data.get("project")
        project = get_object_or_404(Project, pk=project_id)

        import datetime
        date_val = None
        raw_date = data.get("report_date", "").strip()
        if raw_date:
            try:
                date_val = datetime.date.fromisoformat(raw_date)
            except ValueError:
                pass

        report = Report.objects.create(
            project=project,
            title=data.get("title", "Penetration Test Report").strip(),
            executive_summary=data.get("executive_summary", "").strip(),
            company_name=data.get("company_name", "").strip(),
            assessor_name=data.get("assessor_name", "").strip(),
            report_date=date_val,
            include_evidence="include_evidence" in data,
            include_remediation="include_remediation" in data,
            min_severity=data.get("min_severity", "info"),
            engagement_type=data.get("engagement_type", "black-box"),
            methodology_notes=data.get("methodology_notes", "").strip(),
            scope_notes=data.get("scope_notes", "").strip(),
            created_by=request.user,
        )

        # Attach selected targets (empty list = all targets)
        target_ids = data.getlist("target_ids")
        if target_ids:
            from apps.targets.models import Target
            targets_qs = Target.objects.filter(
                pk__in=target_ids, project=project
            )
            report.targets.set(targets_qs)

        return redirect("report_builder", pk=report.pk)

    # Pre-build a project→targets mapping for the JS dynamic checklist
    projects_with_targets = []
    for p in projects:
        targets = list(p.targets.values("id", "value", "target_type"))
        projects_with_targets.append({
            "id": str(p.pk),
            "name": p.name,
            "targets": [
                {"id": str(t["id"]), "value": t["value"], "type": t["target_type"]}
                for t in targets
            ],
        })

    return render(request, "reports/create.html", {
        "projects": projects,
        "projects_json": json.dumps(projects_with_targets),
        "today": timezone.now().date().isoformat(),
    })


# ─── Builder ──────────────────────────────────────────────────────────────────

@login_required
def report_builder(request, pk):
    report = _user_report(request.user, pk)
    from apps.results.models import Finding
    from django.db.models import Q

    # Include findings linked directly to the project OR via scan_job (legacy records
    # created before the bulk_create project-FK fix had project=None).
    all_findings = Finding.objects.filter(
        Q(project=report.project) |
        Q(project__isnull=True, scan_job__project=report.project),
        status__in=["open", "confirmed", "mitigated"],
    ).order_by("severity", "-created_at")

    selected_ids = [str(fid) for fid in (report.finding_ids or [])]

    return render(request, "reports/builder.html", {
        "report": report,
        "all_findings": all_findings,
        "selected_ids": json.dumps(selected_ids),
    })


@login_required
@require_POST
def report_builder_save(request, pk):
    report = _user_report(request.user, pk)

    data = request.POST
    report.title = data.get("title", report.title).strip()
    report.executive_summary = data.get("executive_summary", report.executive_summary).strip()
    report.company_name = data.get("company_name", report.company_name).strip()
    report.assessor_name = data.get("assessor_name", report.assessor_name).strip()
    report.include_evidence = "include_evidence" in data
    report.include_remediation = "include_remediation" in data
    report.min_severity = data.get("min_severity", report.min_severity)
    report.engagement_type = data.get("engagement_type", report.engagement_type)
    report.methodology_notes = data.get("methodology_notes", report.methodology_notes).strip()
    report.scope_notes = data.get("scope_notes", report.scope_notes).strip()

    # Ordered finding IDs from POST
    ids_raw = data.get("finding_ids", "[]")
    try:
        report.finding_ids = json.loads(ids_raw)
    except (ValueError, TypeError):
        report.finding_ids = []

    report.status = "draft"
    report.save()
    messages.success(request, "Report configuration saved.")
    return redirect("report_builder", pk=report.pk)


# ─── Generate ─────────────────────────────────────────────────────────────────

@login_required
@require_POST
def report_generate(request, pk):
    report = _user_report(request.user, pk)
    fmt = request.POST.get("format", "html")
    valid_formats = {"html", "pdf", "json", "markdown"}
    if fmt not in valid_formats:
        fmt = "html"

    from .tasks import generate_report_task
    task = generate_report_task.delay(str(report.pk), fmt)
    report.status = "generating"
    report.celery_task_id = task.id
    report.save(update_fields=["status", "celery_task_id"])

    messages.info(request, f"Generating {fmt.upper()} report — this may take a moment.")
    return redirect("report_detail", pk=report.pk)


# ─── Detail ───────────────────────────────────────────────────────────────────

@login_required
def report_detail(request, pk):
    report = _user_report(request.user, pk)
    from apps.reports.generators import (
        _get_findings, _count_by_severity, build_risk_matrix,
        _get_methodology, _get_sow_targets, _build_wstg_with_coverage, FindingWrapper,
    )
    findings_raw = _get_findings(report)
    findings     = [FindingWrapper(f, i + 1) for i, f in enumerate(findings_raw)]
    counts       = _count_by_severity(findings_raw)
    risk_matrix  = build_risk_matrix(report)
    methodology  = _get_methodology(report)
    targets      = _get_sow_targets(report)
    wstg         = _build_wstg_with_coverage(methodology)
    max_count    = max(counts.values()) if any(counts.values()) else 1
    severity_bars = [
        {"sev": sev, "cnt": counts.get(sev, 0), "pct": int(counts.get(sev, 0) / max_count * 100)}
        for sev in ("critical", "high", "medium", "low", "info")
    ]
    return render(request, "reports/detail.html", {
        "report":            report,
        "findings":          findings,
        "counts":            counts,
        "risk_matrix":       risk_matrix,
        "methodology":       methodology,
        "targets":           targets,
        "wstg_playbook":     wstg,
        "severity_bars":     severity_bars,
        "engagement_type":   getattr(report, "engagement_type", "black-box"),
        "methodology_notes": getattr(report, "methodology_notes", ""),
        "scope_notes":       getattr(report, "scope_notes", ""),
    })


# ─── Download ─────────────────────────────────────────────────────────────────

@login_required
def report_download(request, pk):
    report = _user_report(request.user, pk)
    fmt = request.GET.get("format", report.last_format or "json")

    from django.conf import settings as djsettings
    ext_map = {"pdf": "pdf", "json": "json", "markdown": "md", "html": "html"}
    ext = ext_map.get(fmt, "html")
    file_path = os.path.join(
        djsettings.MEDIA_ROOT, "reports", str(report.pk), f"report.{ext}"
    )

    if not os.path.exists(file_path):
        # Generate on-the-fly for small formats
        from apps.reports.generators import (
            generate_json, generate_markdown, generate_html, generate_pdf
        )
        if fmt == "json":
            content = generate_json(report)
            ct = "application/json"
        elif fmt == "markdown":
            content = generate_markdown(report).encode("utf-8")
            ct = "text/markdown; charset=utf-8"
        elif fmt == "pdf":
            content = generate_pdf(report)
            ct = "application/pdf"
        else:
            content = generate_html(report).encode("utf-8")
            ct = "text/html; charset=utf-8"

        resp = HttpResponse(content, content_type=ct)
        safe_title = "".join(c if c.isalnum() else "_" for c in report.title)[:40]
        resp["Content-Disposition"] = f'attachment; filename="{safe_title}.{ext}"'
        return resp

    ct_map = {
        "pdf": "application/pdf",
        "json": "application/json",
        "md": "text/markdown",
        "html": "text/html",
    }
    ct = ct_map.get(ext, "application/octet-stream")
    safe_title = "".join(c if c.isalnum() else "_" for c in report.title)[:40]
    resp = FileResponse(open(file_path, "rb"), content_type=ct)
    resp["Content-Disposition"] = f'attachment; filename="{safe_title}.{ext}"'
    return resp


# ─── Risk matrix API ─────────────────────────────────────────────────────────

@login_required
def report_risk_matrix(request, pk):
    report = _user_report(request.user, pk)
    from apps.reports.generators import build_risk_matrix
    data = build_risk_matrix(report)
    return JsonResponse(data)
