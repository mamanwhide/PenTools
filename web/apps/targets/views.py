import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST
from django.http import JsonResponse
from apps.targets.models import Target, Project


# ─── Projects ────────────────────────────────────────────────────────────────

@login_required
def project_list(request):
    projects = (
        Project.objects.filter(owner=request.user) |
        Project.objects.filter(members=request.user)
    ).distinct().prefetch_related("targets")
    return render(request, "targets/project_list.html", {"projects": projects})


@login_required
def project_create(request):
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        description = request.POST.get("description", "").strip()
        if name:
            project = Project.objects.create(
                name=name,
                description=description,
                owner=request.user,
            )
            return redirect("targets:project_detail", pk=project.pk)
        return render(request, "targets/project_form.html", {
            "action": "Create",
            "error": "Project name is required.",
        })
    return render(request, "targets/project_form.html", {"action": "Create"})


@login_required
def project_detail(request, pk):
    project = get_object_or_404(
        Project.objects.filter(owner=request.user) | Project.objects.filter(members=request.user),
        pk=pk,
    )
    targets = project.targets.all()
    recent_scans = project.scan_jobs.select_related("target").order_by("-created_at")[:20]
    return render(request, "targets/project_detail.html", {
        "project": project,
        "targets": targets,
        "recent_scans": recent_scans,
    })


@login_required
@require_POST
def project_delete(request, pk):
    project = get_object_or_404(Project, pk=pk, owner=request.user)
    project.delete()
    return redirect("targets:project_list")


# ─── Targets ─────────────────────────────────────────────────────────────────

@login_required
def target_create(request, project_pk):
    project = get_object_or_404(Project, pk=project_pk, owner=request.user)
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        target_type = request.POST.get("target_type", "url")
        value = request.POST.get("value", "").strip()
        description = request.POST.get("description", "").strip()
        is_in_scope = "is_in_scope" in request.POST
        if name and value:
            Target.objects.create(
                project=project,
                name=name,
                target_type=target_type,
                value=value,
                description=description,
                created_by=request.user,
            )
            return redirect("targets:project_detail", pk=project.pk)
        return render(request, "targets/target_form.html", {
            "project": project,
            "action": "Add",
            "target_types": Target.TargetType.choices,
            "error": "Name and Value are required.",
            "form_data": {
                "name": name,
                "target_type": target_type,
                "value": value,
                "description": description,
                "is_in_scope": is_in_scope,
            },
        })
    return render(request, "targets/target_form.html", {
        "project": project,
        "action": "Add",
        "target_types": Target.TargetType.choices,
        "form_data": {"target_type": "url", "is_in_scope": True},
    })


@login_required
@require_POST
def target_delete(request, pk):
    target = get_object_or_404(Target, pk=pk, project__owner=request.user)
    project_pk = target.project_id
    target.delete()
    return redirect("targets:project_detail", pk=project_pk)
