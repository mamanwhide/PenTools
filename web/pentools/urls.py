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
    from django.db.models import Q, Sum
    from django.utils import timezone

    today = timezone.now().date()
    qs = ScanJob.objects.filter(created_by=request.user)

    agg = qs.filter(status="done").aggregate(
        critical_sum=Sum("critical_count"),
        high_sum=Sum("high_count"),
    )

    # Active finding counts from the Finding model (more accurate than scan aggregates)
    open_findings = Finding.objects.filter(
        Q(scan_job__created_by=request.user) | Q(created_by=request.user),
        status__in=("open", "confirmed"),
    )

    stats = {
        "scans_today": qs.filter(created_at__date=today).count(),
        "scans_total": qs.count(),
        "critical":    agg["critical_sum"] or 0,
        "high":        agg["high_sum"] or 0,
        "running":     qs.filter(status__in=["pending", "running"]).count(),
        "open_findings": open_findings.count(),
        "open_critical": open_findings.filter(severity="critical").count(),
    }
    recent_jobs = qs.select_related("target", "project").order_by("-created_at")[:10]
    return render(request, "dashboard/index.html", {"recent_jobs": recent_jobs, **stats})


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
