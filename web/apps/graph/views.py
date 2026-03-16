"""
Graph views — Sprint 3
======================
GraphDataBuilder: builds Cytoscape-ready JSON (nodes + edges) from DB.
Endpoints:
  GET  /graph/<project_id>/          — main graph page
  GET  /api/v1/graph/<project_id>/   — JSON data for Cytoscape
  POST /api/v1/graph/<project_id>/finding/<finding_id>/update/ — mark confirmed / add note
  GET  /api/v1/graph/<project_id>/findings/csv/ — CSV export
"""
from __future__ import annotations

import csv
import io
import json

from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_POST, require_GET

from apps.targets.models import Project, Target
from apps.scans.models import ScanJob
from apps.results.models import Finding


# ─── helpers ─────────────────────────────────────────────────────────────────

def _project_for_user(user, project_id):
    return get_object_or_404(
        Project.objects.filter(owner=user) | Project.objects.filter(members=user),
        pk=project_id,
    )


SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#eab308",
    "low":      "#38bdf8",
    "info":     "#64748b",
}


# ─── GraphDataBuilder ─────────────────────────────────────────────────────────

def build_graph(project: Project) -> dict:
    """
    Returns Cytoscape-ready dict:
      { "nodes": [...], "edges": [...] }

    Node types:
      target     — hexagon, dark border
      port       — diamond, gray
      endpoint   — rectangle, teal
      finding    — circle, severity color
      module_run — small dot, purple

    Edge types:
      belongs_to  — target → project (implicit, always present)
      scanned_by  — target → module_run
      found_at    — module_run → finding
      has_port    — target → finding (port findings)
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_nodes: set[str] = set()

    def add_node(nid: str, data: dict):
        if nid not in seen_nodes:
            seen_nodes.add(nid)
            nodes.append({"data": {"id": nid, **data}})

    def add_edge(eid: str, source: str, target: str, data: dict):
        edges.append({"data": {"id": eid, "source": source, "target": target, **data}})

    # ── Project root node ────────────────────────────────────────────
    project_nid = f"project-{project.id}"
    add_node(project_nid, {
        "label": project.name,
        "node_type": "project",
        "description": project.description or "",
    })

    # ── Targets ──────────────────────────────────────────────────────
    targets = list(Target.objects.filter(project=project))
    for t in targets:
        tnid = f"target-{t.id}"
        add_node(tnid, {
            "label": t.name,
            "node_type": "target",
            "target_type": t.target_type,
            "value": t.value,
            "is_in_scope": t.is_in_scope,
            "target_id": str(t.id),
        })
        add_edge(f"e-proj-{t.id}", project_nid, tnid, {
            "edge_type": "contains",
            "label": "",
        })

    # ── ScanJobs ──────────────────────────────────────────────────────
    jobs = list(ScanJob.objects.filter(project=project).select_related("target"))
    for job in jobs:
        jnid = f"job-{job.id}"
        add_node(jnid, {
            "label": job.module_id,
            "node_type": "module_run",
            "status": job.status,
            "module_id": job.module_id,
            "finding_count": job.finding_count,
            "created_at": job.created_at.isoformat(),
            "job_id": str(job.id),
        })
        # edge from target (if bound) or project root
        src = f"target-{job.target_id}" if job.target_id and f"target-{job.target_id}" in seen_nodes else project_nid
        add_edge(f"e-job-{job.id}", src, jnid, {
            "edge_type": "scanned_by",
            "label": job.module_id,
        })

    # ── Findings ──────────────────────────────────────────────────────
    findings = list(
        Finding.objects.filter(scan_job__project=project)
        .select_related("scan_job")
        .order_by("-scan_job__created_at")
    )
    for f in findings:
        fnid = f"finding-{f.id}"
        color = SEVERITY_COLORS.get(f.severity, "#64748b")
        add_node(fnid, {
            "label": f.title[:60],
            "node_type": "finding",
            "severity": f.severity,
            "color": color,
            "url": f.url,
            "description": f.description[:300],
            "evidence": f.evidence[:300],
            "remediation": f.remediation[:300],
            "status": f.status,
            "cvss_score": str(f.cvss_score) if f.cvss_score else "",
            "cve_id": f.cve_id,
            "cwe_id": f.cwe_id,
            "notes": f.notes,
            "finding_id": str(f.id),
            "job_id": str(f.scan_job_id),
        })
        src_job = f"job-{f.scan_job_id}"
        add_edge(f"e-finding-{f.id}", src_job, fnid, {
            "edge_type": "found_at",
            "label": f.severity.upper(),
            "severity": f.severity,
            "color": color,
        })

    return {"nodes": nodes, "edges": edges}


# ─── Views ────────────────────────────────────────────────────────────────────

@login_required
def graph_page(request, project_id):
    """Main graph page — HTML shell, data loaded via API."""
    project = _project_for_user(request.user, project_id)
    stats = {
        "target_count": Target.objects.filter(project=project).count(),
        "scan_count": ScanJob.objects.filter(project=project).count(),
        "finding_count": Finding.objects.filter(scan_job__project=project).count(),
        "critical_count": Finding.objects.filter(scan_job__project=project, severity="critical").count(),
        "high_count": Finding.objects.filter(scan_job__project=project, severity="high").count(),
    }
    return render(request, "graph/project_graph.html", {
        "project": project,
        "project_id": str(project.id),
        "stats": stats,
    })


@login_required
@require_GET
def graph_data_api(request, project_id):
    """Return Cytoscape JSON for a project."""
    project = _project_for_user(request.user, project_id)
    data = build_graph(project)
    return JsonResponse(data)


@login_required
@require_POST
def finding_update_api(request, project_id, finding_id):
    """Update a finding's status or notes."""
    project = _project_for_user(request.user, project_id)
    finding = get_object_or_404(Finding, id=finding_id, scan_job__project=project)

    try:
        body = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)

    update_fields = []
    if "status" in body:
        allowed = {c[0] for c in Finding.Status.choices}
        if body["status"] not in allowed:
            return JsonResponse({"error": "Invalid status"}, status=400)
        finding.status = body["status"]
        update_fields.append("status")

    if "notes" in body:
        finding.notes = str(body["notes"])[:2000]
        update_fields.append("notes")

    if update_fields:
        finding.save(update_fields=update_fields)

    return JsonResponse({
        "id": str(finding.id),
        "status": finding.status,
        "notes": finding.notes,
    })


@login_required
@require_GET
def findings_csv_api(request, project_id):
    """Export all findings in a project as CSV."""
    project = _project_for_user(request.user, project_id)
    findings = Finding.objects.filter(
        scan_job__project=project
    ).select_related("scan_job").order_by("-scan_job__created_at", "severity")

    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
    writer.writerow([
        "Module", "Severity", "Title", "URL",
        "Description", "Evidence", "Remediation",
        "CVSS", "CVE", "CWE", "Status", "Notes",
    ])
    for f in findings:
        writer.writerow([
            f.scan_job.module_id,
            f.severity,
            f.title,
            f.url,
            f.description,
            f.evidence,
            f.remediation,
            str(f.cvss_score) if f.cvss_score else "",
            f.cve_id,
            f.cwe_id,
            f.status,
            f.notes,
        ])

    buf.seek(0)
    filename = f"findings-{project.name.lower().replace(' ', '-')}.csv"
    resp = HttpResponse(buf.read(), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


@login_required
@require_GET
def graph_json_export(request, project_id):
    """Export graph as JSON (shareable)."""
    project = _project_for_user(request.user, project_id)
    data = build_graph(project)
    data["meta"] = {
        "project": project.name,
        "exported_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }
    resp = JsonResponse(data, json_dumps_params={"indent": 2})
    filename = f"graph-{project.name.lower().replace(' ', '-')}.json"
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp
