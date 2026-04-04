import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse, Http404
from django.utils.decorators import method_decorator
from apps.scans.models import ScanJob, ScanLog, ScheduledScan, ScanDiffReport, ScanChain
from apps.modules.engine import ModuleRegistry
from apps.targets.models import Target, Project


@login_required
def scan_dashboard(request):
    """Recent scans for the current user."""
    jobs = ScanJob.objects.filter(created_by=request.user).select_related("target", "project")[:50]
    return render(request, "scans/dashboard.html", {"jobs": jobs})


@login_required
def scan_create(request, module_id):
    """
    GET  → render the module's dynamic parameter form.
    POST → create ScanJob and dispatch Celery task.
    """
    registry = ModuleRegistry.instance()
    module = registry.get(module_id)
    if module is None:
        raise Http404(f"Module '{module_id}' not found.")

    projects = Project.objects.filter(members=request.user) | Project.objects.filter(owner=request.user)
    projects = projects.distinct()

    if request.method == "POST":
        raw_params = {}
        for key, value in request.POST.items():
            if key.startswith("csrf"):
                continue
            raw_params[key] = value

        # Handle checkbox groups (multiple values)
        for key in request.POST:
            vals = request.POST.getlist(key)
            if len(vals) > 1:
                raw_params[key] = vals

        # Handle file uploads — save to a temp path and store the path as param value
        import os, uuid as _uuid
        from django.conf import settings as _settings
        for file_key, uploaded_file in request.FILES.items():
            scan_upload_dir = os.path.join(
                getattr(_settings, "SCAN_OUTPUT_DIR", "/tmp/pentools"),
                "uploads",
            )
            os.makedirs(scan_upload_dir, exist_ok=True)
            ext = os.path.splitext(uploaded_file.name)[1]
            dest_name = f"{_uuid.uuid4().hex}{ext}"
            dest_path = os.path.join(scan_upload_dir, dest_name)
            with open(dest_path, "wb") as fh:
                for chunk in uploaded_file.chunks():
                    fh.write(chunk)
            raw_params[file_key] = dest_path

        target_id = raw_params.pop("target_id", None)
        project_id = raw_params.pop("project_id", None)

        target = None
        project = None
        if project_id:
            # HIGH-03: verify the user actually owns or is a member of this project
            project = get_object_or_404(
                Project.objects.filter(owner=request.user) | Project.objects.filter(members=request.user),
                id=project_id,
            )
        if target_id:
            if project:
                # HIGH-03/MED-06: target must belong to the resolved project
                target = get_object_or_404(Target, id=target_id, project=project)
            else:
                target = get_object_or_404(Target, id=target_id)

        # Encrypt fields marked sensitive=True in the module schema before DB insert
        from pentools.crypto import encrypt_sensitive_params
        encrypted_params = encrypt_sensitive_params(raw_params, module)

        job = ScanJob.objects.create(
            module_id=module.id,
            params=encrypted_params,
            created_by=request.user,
            target=target,
            project=project,
            status=ScanJob.Status.PENDING,
        )

        # Dispatch Celery task
        from apps.scans.tasks import execute_module
        task = execute_module.apply_async(
            args=[str(job.id)],
            queue=module.celery_queue,
        )
        job.celery_task_id = task.id
        job.save(update_fields=["celery_task_id"])

        return redirect("scans:detail", job_id=str(job.id))

    schema = module.schema_to_dict()

    # Build a project → targets map so the frontend can populate the target dropdown
    all_targets = Target.objects.filter(project__in=projects).select_related("project")
    targets_by_project: dict[str, list] = {}
    for t in all_targets:
        pid = str(t.project_id)
        targets_by_project.setdefault(pid, []).append({
            "id": str(t.id),
            "name": t.name,
            "value": t.value,
            "type": t.target_type,
        })

    return render(request, "scans/create.html", {
        "module": module,
        "schema": schema,
        "schema_json": json.dumps(schema),
        "projects": projects,
        "targets_by_project_json": json.dumps(targets_by_project),
    })


@login_required
def scan_detail(request, job_id):
    """Live scan view with WebSocket log stream."""
    job = get_object_or_404(ScanJob, id=job_id)

    # Only owner or admin can access (HIGH-08: use custom role, not Django is_staff)
    if job.created_by != request.user and not request.user.is_admin_role:
        raise Http404()

    recent_logs = ScanLog.objects.filter(scan_job=job).order_by("-id")[:200]
    return render(request, "scans/detail.html", {
        "job": job,
        "recent_logs": reversed(list(recent_logs)),
    })


@login_required
def scan_list(request):
    jobs = ScanJob.objects.filter(created_by=request.user).order_by("-created_at")
    status_filter = request.GET.get("status")
    if status_filter:
        jobs = jobs.filter(status=status_filter)
    return render(request, "scans/list.html", {
        "jobs": jobs[:100],
        "status_filter": status_filter,
        "status_choices": ScanJob.Status.choices,
    })


@login_required
@require_POST
def scan_cancel(request, job_id):
    job = get_object_or_404(ScanJob, id=job_id, created_by=request.user)
    if job.celery_task_id and job.status in (ScanJob.Status.PENDING, ScanJob.Status.RUNNING):
        from pentools.celery import app as celery_app
        celery_app.control.revoke(job.celery_task_id, terminate=True, signal="SIGTERM")
        job.status = ScanJob.Status.CANCELLED
        job.save(update_fields=["status"])
    return JsonResponse({"ok": True, "status": job.status})


@login_required
@require_POST
def scan_retry(request, job_id):
    """Clone a failed/cancelled job and re-dispatch it."""
    original = get_object_or_404(ScanJob, id=job_id, created_by=request.user)
    if original.status not in (ScanJob.Status.FAILED, ScanJob.Status.CANCELLED):
        from django.http import HttpResponseBadRequest
        return HttpResponseBadRequest("Can only retry failed or cancelled scans.")

    registry = ModuleRegistry.instance()
    module = registry.get(original.module_id)
    if module is None:
        raise Http404(f"Module '{original.module_id}' not found.")

    new_job = ScanJob.objects.create(
        module_id=original.module_id,
        params=original.params,
        created_by=request.user,
        target=original.target,
        project=original.project,
        status=ScanJob.Status.PENDING,
    )
    from apps.scans.tasks import execute_module
    task = execute_module.apply_async(
        args=[str(new_job.id)],
        queue=module.celery_queue,
    )
    new_job.celery_task_id = task.id
    new_job.save(update_fields=["celery_task_id"])
    return redirect("scans:detail", job_id=str(new_job.id))


# ─── Scheduled Scans ─────────────────────────────────────────────────────────

@login_required
def schedule_list(request):
    """List all scheduled scans belonging to the current user."""
    schedules = ScheduledScan.objects.filter(created_by=request.user).order_by("-created_at")
    return render(request, "scans/schedule_list.html", {"schedules": schedules})


@login_required
def schedule_create(request, module_id):
    """
    GET  → render schedule creation form for the given module.
    POST → create ScheduledScan + celery-beat PeriodicTask.
    """
    registry = ModuleRegistry.instance()
    module = registry.get(module_id)
    if module is None:
        raise Http404(f"Module '{module_id}' not found.")

    projects = (
        Project.objects.filter(members=request.user) | Project.objects.filter(owner=request.user)
    ).distinct()

    if request.method == "POST":
        raw_params = {k: v for k, v in request.POST.items() if not k.startswith("csrf")}
        for key in request.POST:
            vals = request.POST.getlist(key)
            if len(vals) > 1:
                raw_params[key] = vals

        name        = raw_params.pop("schedule_name", f"Scheduled {module.name}")
        schedule    = raw_params.pop("schedule_freq", ScheduledScan.Schedule.DAILY)
        project_id  = raw_params.pop("project_id", None)
        target_id   = raw_params.pop("target_id", None)

        target  = get_object_or_404(Target, id=target_id) if target_id else None
        project = get_object_or_404(Project, id=project_id) if project_id else None

        sched = ScheduledScan.objects.create(
            name=name,
            module_id=module.id,
            params=raw_params,
            schedule=schedule,
            is_active=True,
            created_by=request.user,
            project=project,
            target=target,
        )
        # Register with celery-beat (signal handler does this, but call explicitly too)
        _register_periodic_task(sched)
        return redirect("scans:schedule_list")

    schema = module.schema_to_dict()
    all_targets = Target.objects.filter(project__in=projects).select_related("project")
    targets_by_project: dict[str, list] = {}
    for t in all_targets:
        targets_by_project.setdefault(str(t.project_id), []).append({
            "id": str(t.id), "name": t.name, "value": t.value, "type": t.target_type,
        })
    return render(request, "scans/schedule_create.html", {
        "module": module,
        "schema": schema,
        "schema_json": json.dumps(schema),
        "projects": projects,
        "targets_by_project_json": json.dumps(targets_by_project),
        "schedule_choices": ScheduledScan.Schedule.choices,
    })


@login_required
@require_POST
def schedule_toggle(request, schedule_id):
    """Toggle is_active on a scheduled scan (pause/resume)."""
    sched = get_object_or_404(ScheduledScan, id=schedule_id, created_by=request.user)
    sched.is_active = not sched.is_active
    sched.save(update_fields=["is_active"])
    # Sync with celery-beat PeriodicTask
    try:
        from django_celery_beat.models import PeriodicTask
        if sched.periodic_task_name:
            PeriodicTask.objects.filter(name=sched.periodic_task_name).update(enabled=sched.is_active)
    except Exception:
        pass
    return JsonResponse({"ok": True, "is_active": sched.is_active})


@login_required
@require_POST
def schedule_delete(request, schedule_id):
    """Delete a scheduled scan and its celery-beat PeriodicTask."""
    sched = get_object_or_404(ScheduledScan, id=schedule_id, created_by=request.user)
    try:
        from django_celery_beat.models import PeriodicTask
        if sched.periodic_task_name:
            PeriodicTask.objects.filter(name=sched.periodic_task_name).delete()
    except Exception:
        pass
    sched.delete()
    return JsonResponse({"ok": True})


def _register_periodic_task(sched: ScheduledScan):
    """Create/update the django-celery-beat PeriodicTask for this ScheduledScan."""
    try:
        from django_celery_beat.models import PeriodicTask, CrontabSchedule

        crontab_kwargs = {
            "hourly":   {"minute": "0",                  "hour": "*",  "day_of_week": "*", "day_of_month": "*", "month_of_year": "*"},
            "daily":    {"minute": "0",                  "hour": "3",  "day_of_week": "*", "day_of_month": "*", "month_of_year": "*"},
            "weekly":   {"minute": "0",                  "hour": "3",  "day_of_week": "1", "day_of_month": "*", "month_of_year": "*"},
            "biweekly": {"minute": "0",                  "hour": "3",  "day_of_week": "1", "day_of_month": "1-14", "month_of_year": "*"},
            "monthly":  {"minute": "0",                  "hour": "3",  "day_of_week": "*", "day_of_month": "1",    "month_of_year": "*"},
        }.get(sched.schedule, {"minute": "0", "hour": "3", "day_of_week": "*", "day_of_month": "*", "month_of_year": "*"})

        crontab, _ = CrontabSchedule.objects.get_or_create(**crontab_kwargs)

        task_name = f"scheduled_scan_{sched.id}"
        PeriodicTask.objects.update_or_create(
            name=task_name,
            defaults={
                "crontab": crontab,
                "task": "scans.execute_scheduled_scan",
                "args": json.dumps([str(sched.id)]),
                "enabled": sched.is_active,
            },
        )
        sched.periodic_task_name = task_name
        sched.save(update_fields=["periodic_task_name"])
    except Exception:
        pass  # celery-beat tables may not exist in test env


# ─── Scan Diff Reports ────────────────────────────────────────────────────────

@login_required
def diff_list(request):
    """List diff reports for the current user's projects."""
    user_projects = (
        Project.objects.filter(members=request.user) | Project.objects.filter(owner=request.user)
    ).distinct()

    diffs = (
        ScanDiffReport.objects
        .filter(project__in=user_projects)
        .select_related("baseline_job", "current_job", "project")
        .order_by("-created_at")[:100]
    )
    return render(request, "scans/diff_list.html", {"diffs": diffs})


@login_required
def diff_detail(request, diff_id):
    """Show the detailed diff between two scans."""
    diff = get_object_or_404(ScanDiffReport, id=diff_id)

    # Access control: must be project member or staff
    if diff.project:
        user_projects = (
            Project.objects.filter(members=request.user) | Project.objects.filter(owner=request.user)
        ).distinct()
        if diff.project not in user_projects and not request.user.is_admin_role:
            raise Http404()
    elif not request.user.is_admin_role:
        raise Http404()

    return render(request, "scans/diff_detail.html", {"diff": diff})


# ─── Scan Chains ─────────────────────────────────────────────────────────────

@login_required
def chain_list(request):
    """List all active scan chains."""
    chains = ScanChain.objects.filter(created_by=request.user).order_by("parent_module", "child_module")
    return render(request, "scans/chain_list.html", {"chains": chains})


@login_required
@require_POST
def chain_toggle(request, chain_id):
    chain = get_object_or_404(ScanChain, id=chain_id, created_by=request.user)
    chain.is_active = not chain.is_active
    chain.save(update_fields=["is_active"])
    return JsonResponse({"ok": True, "is_active": chain.is_active})


@login_required
@require_POST
def chain_delete(request, chain_id):
    chain = get_object_or_404(ScanChain, id=chain_id, created_by=request.user)
    chain.delete()
    return JsonResponse({"ok": True})


@login_required
def chain_create(request):
    """Create a scan chain rule."""
    registry = ModuleRegistry.instance()
    modules = sorted(registry.all(), key=lambda m: m.id)

    if request.method == "POST":
        name          = request.POST.get("name", "")
        parent_module = request.POST.get("parent_module", "")
        child_module  = request.POST.get("child_module", "")
        trigger_on    = request.POST.get("trigger_on", ScanChain.TriggerOn.DONE)
        try:
            param_mapping = json.loads(request.POST.get("param_mapping", "{}"))
            base_params   = json.loads(request.POST.get("base_params", "{}"))
        except json.JSONDecodeError:
            return render(request, "scans/chain_create.html", {
                "modules": modules, "error": "Invalid JSON in param_mapping or base_params."
            })

        ScanChain.objects.create(
            name=name,
            parent_module=parent_module,
            child_module=child_module,
            trigger_on=trigger_on,
            param_mapping=param_mapping,
            base_params=base_params,
            is_active=True,
            created_by=request.user,
        )
        return redirect("scans:chain_list")

    return render(request, "scans/chain_create.html", {
        "modules": modules,
        "trigger_choices": ScanChain.TriggerOn.choices,
    })
