"""Scan REST API — used by HTMX partial updates and JS."""
from django.urls import path
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.shortcuts import get_object_or_404
from apps.scans.models import ScanJob, ScanLog


@login_required
def api_job_status(request, job_id):
    job = get_object_or_404(ScanJob, id=job_id, created_by=request.user)
    return JsonResponse({
        "id": str(job.id),
        "status": job.status,
        "progress": job.progress,
        "finding_count": job.finding_count,
        "critical_count": job.critical_count,
        "high_count": job.high_count,
        "duration": job.duration_seconds,
    })


@login_required
def api_job_logs(request, job_id):
    job = get_object_or_404(ScanJob, id=job_id, created_by=request.user)
    since_id = request.GET.get("since", 0)
    logs = ScanLog.objects.filter(scan_job=job, id__gt=since_id).order_by("id")[:500]
    data = [
        {"id": l.id, "level": l.level, "message": l.message, "ts": l.timestamp.isoformat()}
        for l in logs
    ]
    return JsonResponse({"logs": data})


@login_required
def api_job_findings(request, job_id):
    job = get_object_or_404(ScanJob, id=job_id, created_by=request.user)
    findings = job.findings.all().values(
        "id", "title", "severity", "url", "status", "cve_id", "cwe_id"
    )
    return JsonResponse({"findings": list(findings)})


# ── Save / Load Configs ────────────────────────────────────────────────

@login_required
def api_list_configs(request, module_id):
    """List saved parameter configs for the current user + module."""
    from apps.scans.models import ScanJobTemplate
    templates = list(
        ScanJobTemplate.objects.filter(
            module_id=module_id, created_by=request.user
        ).values("id", "name", "params", "created_at")
    )
    # Serialize timestamps
    for t in templates:
        t["id"] = str(t["id"])
        t["created_at"] = t["created_at"].isoformat()
    return JsonResponse({"templates": templates})


@login_required
@require_POST
def api_save_config(request, module_id):
    """Save (or overwrite) a named parameter config for a module."""
    import json as _json
    from apps.scans.models import ScanJobTemplate
    try:
        body = _json.loads(request.body)
    except Exception:
        return JsonResponse({"error": "Invalid JSON body"}, status=400)
    name = body.get("name", "").strip()
    params = body.get("params", {})
    if not name:
        return JsonResponse({"error": "Config name is required"}, status=400)
    template, created = ScanJobTemplate.objects.update_or_create(
        module_id=module_id,
        name=name,
        created_by=request.user,
        defaults={"params": params},
    )
    return JsonResponse({"ok": True, "id": str(template.id), "created": created})


@login_required
@require_POST
def api_delete_config(request, config_id):
    """Delete a saved config by UUID."""
    import uuid as _uuid
    from apps.scans.models import ScanJobTemplate
    tpl = get_object_or_404(ScanJobTemplate, id=config_id, created_by=request.user)
    tpl.delete()
    return JsonResponse({"ok": True})


urlpatterns = [
    path("<uuid:job_id>/status/", api_job_status, name="api_job_status"),
    path("<uuid:job_id>/logs/", api_job_logs, name="api_job_logs"),
    path("<uuid:job_id>/findings/", api_job_findings, name="api_job_findings"),
    path("configs/<str:module_id>/", api_list_configs, name="api_list_configs"),
    path("configs/<str:module_id>/save/", api_save_config, name="api_save_config"),
    path("configs/delete/<uuid:config_id>/", api_delete_config, name="api_delete_config"),
]
