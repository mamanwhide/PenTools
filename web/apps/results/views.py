"""
Finding management views — list, detail, create (manual), update status, CVSS widget.
"""
from __future__ import annotations
import json
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST, require_http_methods
from django.contrib import messages
from django.db.models import Q, Count
from django.core.paginator import Paginator

from .models import Finding, FindingStatusHistory


# ─── helper ──────────────────────────────────────────────────────────────────

def _owned_finding(user, pk):
    """Get finding the user has access to (owns project or is superuser)."""
    f = get_object_or_404(Finding, pk=pk)
    if user.is_superuser:
        return f
    if f.project and (f.project.owner == user or f.project.members.filter(pk=user.pk).exists()):
        return f
    if f.scan_job and f.scan_job.created_by == user:
        return f
    from django.core.exceptions import PermissionDenied
    raise PermissionDenied


# ─── Finding list / dashboard ────────────────────────────────────────────────

@login_required
def finding_list(request):
    """All findings visible to the current user, with filtering."""
    from apps.targets.models import Project

    projects = Project.objects.filter(
        Q(owner=request.user) | Q(members=request.user)
    ).distinct()

    qs = Finding.objects.filter(
        Q(project__in=projects) | Q(scan_job__created_by=request.user)
    ).select_related("scan_job", "project", "assigned_to").distinct()

    # Filters
    severity = request.GET.get("severity")
    status = request.GET.get("status")
    project_id = request.GET.get("project")
    q = request.GET.get("q", "").strip()
    is_manual = request.GET.get("manual")

    if severity:
        qs = qs.filter(severity=severity)
    if status:
        qs = qs.filter(status=status)
    if project_id:
        qs = qs.filter(project_id=project_id)
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(url__icontains=q) | Q(cve_id__icontains=q))
    if is_manual == "1":
        qs = qs.filter(is_manual=True)

    # Stats
    stats = {
        "total":    qs.count(),
        "critical": qs.filter(severity="critical").count(),
        "high":     qs.filter(severity="high").count(),
        "medium":   qs.filter(severity="medium").count(),
        "open":     qs.filter(status="open").count(),
    }

    paginator = Paginator(qs.order_by("-created_at"), 50)
    page = paginator.get_page(request.GET.get("page", 1))

    return render(request, "findings/list.html", {
        "page": page,
        "stats": stats,
        "projects": projects,
        "severity_choices": Finding.Severity.choices,
        "status_choices": Finding.Status.choices,
        "filters": {
            "severity": severity, "status": status,
            "project": project_id, "q": q, "manual": is_manual,
        },
    })


@login_required
def finding_detail(request, pk):
    finding = _owned_finding(request.user, pk)
    history = finding.status_history.select_related("changed_by").order_by("changed_at")
    return render(request, "findings/detail.html", {
        "finding": finding,
        "history": history,
        "status_choices": Finding.Status.choices,
    })


# ─── Manual finding entry ─────────────────────────────────────────────────────

@login_required
@require_http_methods(["GET", "POST"])
def finding_create(request):
    from apps.targets.models import Project

    projects = Project.objects.filter(
        Q(owner=request.user) | Q(members=request.user)
    ).distinct()

    if request.method == "POST":
        data = request.POST
        project_id = data.get("project")
        project = None
        if project_id:
            project = get_object_or_404(Project, pk=project_id,
                                        owner=request.user)

        cvss_score = None
        raw_cvss = data.get("cvss_score", "").strip()
        if raw_cvss:
            try:
                cvss_score = float(raw_cvss)
            except ValueError:
                pass

        finding = Finding.objects.create(
            project=project,
            title=data.get("title", "").strip(),
            severity=data.get("severity", "info"),
            url=data.get("url", "").strip(),
            description=data.get("description", "").strip(),
            evidence=data.get("evidence", "").strip(),
            remediation=data.get("remediation", "").strip(),
            cvss_score=cvss_score,
            cvss_vector=data.get("cvss_vector", "").strip(),
            cve_id=data.get("cve_id", "").strip(),
            cwe_id=data.get("cwe_id", "").strip(),
            notes=data.get("notes", "").strip(),
            is_manual=True,
            status="open",
            created_by=request.user,
        )
        FindingStatusHistory.objects.create(
            finding=finding,
            from_status="",
            to_status="open",
            changed_by=request.user,
            note="Manual finding created",
        )
        messages.success(request, f"Finding '{finding.title}' created.")
        return redirect("finding_detail", pk=finding.pk)

    return render(request, "findings/create.html", {
        "projects": projects,
        "severity_choices": Finding.Severity.choices,
        "cwe_suggestions": _CWE_COMMON,
    })


_CWE_COMMON = [
    ("CWE-79",   "Cross-site Scripting (XSS)"),
    ("CWE-89",   "SQL Injection"),
    ("CWE-22",   "Path Traversal"),
    ("CWE-352",  "Cross-Site Request Forgery (CSRF)"),
    ("CWE-200",  "Exposure of Sensitive Information"),
    ("CWE-287",  "Improper Authentication"),
    ("CWE-306",  "Missing Authentication for Critical Function"),
    ("CWE-918",  "Server-Side Request Forgery (SSRF)"),
    ("CWE-611",  "Improper Restriction of XML External Entity Reference"),
    ("CWE-434",  "Unrestricted Upload of File with Dangerous Type"),
    ("CWE-502",  "Deserialization of Untrusted Data"),
    ("CWE-798",  "Use of Hard-coded Credentials"),
]


@login_required
@require_http_methods(["GET", "POST"])
def finding_edit(request, pk):
    finding = _owned_finding(request.user, pk)

    if request.method == "POST":
        data = request.POST
        finding.title = data.get("title", finding.title).strip()
        finding.severity = data.get("severity", finding.severity)
        finding.url = data.get("url", finding.url).strip()
        finding.description = data.get("description", finding.description).strip()
        finding.evidence = data.get("evidence", finding.evidence).strip()
        finding.remediation = data.get("remediation", finding.remediation).strip()
        raw_cvss = data.get("cvss_score", "").strip()
        if raw_cvss:
            try:
                finding.cvss_score = float(raw_cvss)
            except ValueError:
                pass
        finding.cvss_vector = data.get("cvss_vector", finding.cvss_vector).strip()
        finding.cve_id = data.get("cve_id", finding.cve_id).strip()
        finding.cwe_id = data.get("cwe_id", finding.cwe_id).strip()
        finding.notes = data.get("notes", finding.notes).strip()
        finding.save()
        messages.success(request, "Finding updated.")
        return redirect("finding_detail", pk=finding.pk)

    return render(request, "findings/edit.html", {
        "finding": finding,
        "severity_choices": Finding.Severity.choices,
        "cwe_suggestions": _CWE_COMMON,
    })


# ─── Status workflow ──────────────────────────────────────────────────────────

@login_required
@require_POST
def finding_update_status(request, pk):
    finding = _owned_finding(request.user, pk)
    new_status = request.POST.get("status")
    note = request.POST.get("note", "").strip()

    valid = {c[0] for c in Finding.Status.choices}
    if new_status not in valid:
        return JsonResponse({"error": "Invalid status"}, status=400)

    old_status = finding.status
    if old_status != new_status:
        finding.status = new_status
        finding.save(update_fields=["status", "updated_at"])
        FindingStatusHistory.objects.create(
            finding=finding,
            from_status=old_status,
            to_status=new_status,
            changed_by=request.user,
            note=note,
        )

    if request.headers.get("HX-Request"):
        # Return the badge partial for HTMX swap
        return render(request, "findings/_status_badge.html", {"finding": finding})

    return JsonResponse({"status": new_status, "ok": True})


# ─── Duplicate check (HTMX) ──────────────────────────────────────────────────

@login_required
def finding_check_duplicate(request):
    title = request.GET.get("title", "")
    url = request.GET.get("url", "")
    evidence = request.GET.get("evidence", "")[:200]
    import hashlib
    raw = f"{title}|{url}|{evidence}"
    h = hashlib.sha256(raw.encode()).hexdigest()
    existing = Finding.objects.filter(evidence_hash=h).first()
    if existing:
        return render(request, "findings/_duplicate_warning.html", {"existing": existing})
    return HttpResponse("")


# ─── CVSS 3.1 Calculator (HTMX endpoint) ─────────────────────────────────────

@login_required
def cvss_calculator(request):
    """HTMX-friendly CVSS 3.1 scoring calculator."""
    score, rating, vector = None, None, ""

    if request.method == "POST":
        data = request.POST
        try:
            score, rating, vector = _compute_cvss31(data)
        except Exception:
            pass

    return render(request, "findings/cvss_calculator.html", {
        "score": score,
        "rating": rating,
        "vector": vector,
        "is_post": request.method == "POST",
    })


def _compute_cvss31(data):
    """
    Compute CVSS 3.1 base score from the 8 base metrics.
    Returns (score_float, rating_str, vector_str)
    """
    # Attack Vector
    AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    # Attack Complexity
    AC  = {"L": 0.77, "H": 0.44}
    # Privileges Required (scope unchanged / changed affects these)
    PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}
    # User Interaction
    UI  = {"N": 0.85, "R": 0.62}
    # Scope
    S   = data.get("S", "U")
    # Impact metrics
    C_val = {"N": 0.00, "L": 0.22, "H": 0.56}
    I_val = {"N": 0.00, "L": 0.22, "H": 0.56}
    A_val = {"N": 0.00, "L": 0.22, "H": 0.56}

    av = AV.get(data.get("AV", "N"), 0.85)
    ac = AC.get(data.get("AC", "L"), 0.77)
    pr = (PR_C if S == "C" else PR_U).get(data.get("PR", "N"), 0.85)
    ui = UI.get(data.get("UI", "N"), 0.85)
    c  = C_val.get(data.get("C", "N"), 0.0)
    i  = I_val.get(data.get("I", "N"), 0.0)
    a  = A_val.get(data.get("A", "N"), 0.0)

    import math

    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if S == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    else:
        if S == "U":
            score = min(impact + exploitability, 10)
        else:
            score = min(1.08 * (impact + exploitability), 10)
        # Round up to 1 decimal
        score = math.ceil(score * 10) / 10

    if score == 0.0:
        rating = "None"
    elif score < 4.0:
        rating = "Low"
    elif score < 7.0:
        rating = "Medium"
    elif score < 9.0:
        rating = "High"
    else:
        rating = "Critical"

    vector = (
        f"CVSS:3.1/AV:{data.get('AV','N')}/AC:{data.get('AC','L')}"
        f"/PR:{data.get('PR','N')}/UI:{data.get('UI','N')}/S:{S}"
        f"/C:{data.get('C','N')}/I:{data.get('I','N')}/A:{data.get('A','N')}"
    )
    return round(score, 1), rating, vector
