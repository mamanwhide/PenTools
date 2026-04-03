from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect


@login_required
def dashboard(request):
    from apps.scans.models import ScanJob
    from apps.results.models import Finding
    from django.db.models import Q, Count
    from django.db.models.functions import TruncDate
    from django.utils import timezone
    import json as _json
    from datetime import timedelta

    today = timezone.now().date()
    qs = ScanJob.objects.filter(created_by=request.user)

    # All findings visible to this user
    user_findings = Finding.objects.filter(
        Q(scan_job__created_by=request.user) | Q(created_by=request.user),
    )

    # Severity breakdown from Finding model (single query, accurate)
    sev_counts = dict(
        user_findings.values_list("severity").annotate(c=Count("id")).values_list("severity", "c")
    )

    # Open finding counts
    open_findings = user_findings.filter(status__in=("open", "confirmed"))

    # ── Chart data: scan activity last 14 days ──
    day_start = today - timedelta(days=13)
    daily_scans = dict(
        qs.filter(created_at__date__gte=day_start)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(c=Count("id"))
        .values_list("day", "c")
    )
    daily_findings = dict(
        user_findings.filter(created_at__date__gte=day_start)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(c=Count("id"))
        .values_list("day", "c")
    )
    trend_labels = []
    trend_scans = []
    trend_findings = []
    for i in range(14):
        d = day_start + timedelta(days=i)
        trend_labels.append(d.strftime("%b %d"))
        trend_scans.append(daily_scans.get(d, 0))
        trend_findings.append(daily_findings.get(d, 0))

    # ── Chart data: scan status breakdown ──
    status_counts = dict(
        qs.values("status").annotate(c=Count("id")).values_list("status", "c")
    )

    # ── Chart data: finding status breakdown ──
    finding_status_counts = dict(
        user_findings.values("status").annotate(c=Count("id")).values_list("status", "c")
    )

    stats = {
        "scans_today": qs.filter(created_at__date=today).count(),
        "scans_total": qs.count(),
        "critical":    sev_counts.get("critical", 0),
        "high":        sev_counts.get("high", 0),
        "medium":      sev_counts.get("medium", 0),
        "low":         sev_counts.get("low", 0),
        "info":        sev_counts.get("info", 0),
        "running":     qs.filter(status__in=["pending", "running"]).count(),
        "open_findings": open_findings.count(),
        "open_critical": open_findings.filter(severity="critical").count(),
    }

    chart_data = {
        "trend_labels":   _json.dumps(trend_labels),
        "trend_scans":    _json.dumps(trend_scans),
        "trend_findings": _json.dumps(trend_findings),
        "scan_status":    _json.dumps(status_counts),
        "finding_status": _json.dumps(finding_status_counts),
    }

    recent_jobs = qs.select_related("target", "project").order_by("-created_at")[:10]
    return render(request, "dashboard/index.html", {
        "recent_jobs": recent_jobs, **stats, **chart_data,
    })


urlpatterns = [
    # Root redirect
    path("", lambda request: redirect("dashboard", permanent=False)),
    # Dashboard
    path("dashboard/", dashboard, name="dashboard"),
    # Platform UI
    path("", include("apps.accounts.urls")),
    path("scans/", include("apps.scans.urls")),
    path("modules/", include("apps.modules.urls")),
    path("targets/", include("apps.targets.urls")),
    # Sprint 6 — Findings, Reports, Notifications
    path("findings/", include("apps.results.urls")),
    path("reports/", include("apps.reports.urls")),
    path("notifications/", include("apps.notifications.urls")),
    # REST API v1
    path("api/v1/scans/", include("apps.scans.api_urls")),
    path("api/v1/modules/", include("apps.modules.api_urls")),
    # Graph
    path("projects/graph/", include("apps.graph.urls")),
    path("api/v1/graph/", include("apps.graph.api_urls")),
    # Admin
    path("admin-panel/", admin.site.urls),
    # Health check
    path("health/", include("apps.accounts.health_urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
