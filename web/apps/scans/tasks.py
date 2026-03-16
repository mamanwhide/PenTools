"""
Core Celery task: execute any registered module by job_id.
All attack modules are dispatched through this single entry point.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone

from celery import shared_task, Task
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone as dj_tz
from apps.modules.runner import ToolNotFoundError


def _push_ws(group: str, event_type: str, payload: dict):
    """Push a message to a WebSocket channel group (sync wrapper)."""
    layer = get_channel_layer()
    if layer:
        async_to_sync(layer.group_send)(group, {"type": event_type, **payload})


class ExecuteModuleTask(Task):
    """Base Celery task class with streaming helpers."""

    def stream(self, job_id: str, level: str, message: str):
        """Send one log line to the browser via WebSocket + save to DB."""
        from apps.scans.models import ScanLog
        ScanLog.objects.create(scan_job_id=job_id, level=level, message=message[:4096])
        _push_ws(
            f"scan_{job_id}",
            "scan_log",
            {
                "level": level,
                "message": message[:4096],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def update_progress(self, job_id: str, progress: int, status: str = "running"):
        from apps.scans.models import ScanJob
        ScanJob.objects.filter(id=job_id).update(progress=progress, status=status)
        _push_ws(
            f"scan_{job_id}",
            "scan_progress",
            {"progress": progress, "status": status},
        )


@shared_task(bind=True, base=ExecuteModuleTask, name="scans.execute_module")
def execute_module(self, job_id: str):
    """
    Entry point for all module executions.
    Loads the ScanJob, resolves the module, validates params, runs execute().
    """
    from apps.scans.models import ScanJob
    from apps.modules.engine import ModuleRegistry

    try:
        job = ScanJob.objects.get(id=job_id)
    except ScanJob.DoesNotExist:
        # Task received for a job that no longer exists (e.g. DB was reset after task was queued).
        # Discard silently — no action possible.
        return
    job.status = ScanJob.Status.RUNNING
    job.started_at = dj_tz.now()
    # self.request.id is None when the task is called synchronously (e.g. in tests).
    # Fall back to the existing celery_task_id or generate a placeholder.
    job.celery_task_id = self.request.id or job.celery_task_id or str(job.id)
    job.save(update_fields=["status", "started_at", "celery_task_id"])

    self.stream(job_id, "info", f"[{job.module_id}] Starting execution...")

    registry = ModuleRegistry.instance()
    module = registry.get(job.module_id)

    if module is None:
        job.status = ScanJob.Status.FAILED
        job.finished_at = dj_tz.now()
        job.save(update_fields=["status", "finished_at"])
        self.stream(job_id, "error", f"Module '{job.module_id}' not found in registry.")
        return

    try:
        params = module.validate_params(job.params)
    except ValueError as e:
        job.status = ScanJob.Status.FAILED
        job.finished_at = dj_tz.now()
        job.save(update_fields=["status", "finished_at"])
        self.stream(job_id, "error", f"Parameter validation failed: {e}")
        return

    # Build a stream callable for the module to use
    def stream_fn(level: str, message: str):
        self.stream(job_id, level, message)

    try:
        result = module.execute(params=params, job_id=job_id, stream=stream_fn)
    except ToolNotFoundError as exc:
        # Tool binary is simply not installed — don't retry, surface a clear message.
        tool_name = str(exc).split("'")[1] if "'" in str(exc) else str(exc)
        job.status = ScanJob.Status.FAILED
        job.finished_at = dj_tz.now()
        job.save(update_fields=["status", "finished_at"])
        self.stream(job_id, "error",
                    f"Required tool not installed: '{tool_name}'. "
                    f"Rebuild the tools Docker image to include it.")
        _push_ws(f"scan_{job_id}", "scan_complete", {"status": "failed", "duration": None})
        return  # don't raise — no point retrying a missing binary
    except Exception as exc:
        job.status = ScanJob.Status.FAILED
        job.finished_at = dj_tz.now()
        job.save(update_fields=["status", "finished_at"])
        self.stream(job_id, "error", f"Execution error: {exc}")
        _push_ws(f"scan_{job_id}", "scan_complete", {"status": "failed", "duration": None})
        raise

    # Save findings
    findings = result.get("findings", [])
    _save_findings(job, findings)

    # Finalize job
    job.status = ScanJob.Status.DONE if result.get("status") != "failed" else ScanJob.Status.FAILED
    job.finished_at = dj_tz.now()
    job.progress = 100
    job.finding_count = len(findings)
    job.critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    job.high_count = sum(1 for f in findings if f.get("severity") == "high")
    job.save(update_fields=["status", "finished_at", "progress", "finding_count", "critical_count", "high_count"])

    duration = job.duration_seconds
    self.stream(job_id, "success", f"Scan complete. {len(findings)} findings. Duration: {duration}s")

    _push_ws(f"scan_{job_id}", "scan_complete", {
        "status": job.status,
        "finding_count": len(findings),
        "duration": duration,
    })

    # ── Post-completion hooks ─────────────────────────────────────────────────
    metadata = result.get("metadata", {})

    # 1. Generate diff report (compare with previous run of same module+target)
    _generate_diff_report(job, findings)

    # 2. Trigger any scan chains that fire on this module completing
    if job.status == ScanJob.Status.DONE:
        _trigger_scan_chains(job, metadata, self)

    # Notify the project graph channel so live graph viewers see new nodes
    if job.project_id:
        _push_ws(
            f"graph_{job.project_id}",
            "graph_scan_complete",
            {
                "job_id": str(job.id),
                "module_id": job.module_id,
                "finding_count": len(findings),
                "status": job.status,
            },
        )


def _save_findings(job, findings: list[dict]):
    from apps.results.models import Finding
    import hashlib

    objs = []
    for f in findings:
        title    = f.get("title", "Untitled")
        url      = f.get("url", "")
        evidence = f.get("evidence", "")
        raw_hash = f"{title}|{url}|{evidence[:200]}"
        ev_hash  = hashlib.sha256(raw_hash.encode()).hexdigest()

        objs.append(Finding(
            scan_job=job,
            # Explicitly set project so bulk_create (which skips save()) links
            # findings to the correct project. Without this findings are invisible
            # to all report queries that filter by Finding.project.
            project=job.project,
            title=title,
            severity=f.get("severity", "info"),
            url=url,
            description=f.get("description", ""),
            evidence=evidence,
            evidence_hash=ev_hash,
            remediation=f.get("remediation", ""),
            cvss_score=f.get("cvss_score"),
            cve_id=f.get("cve_id", ""),
            cwe_id=f.get("cwe_id", ""),
            raw_data=f,
        ))
    if objs:
        Finding.objects.bulk_create(objs, ignore_conflicts=True)


# ─── Diff Report Generator ────────────────────────────────────────────────────

def _generate_diff_report(current_job, current_findings: list[dict]):
    """
    Compare current job's findings against the previous run of the same
    module on the same target. Creates a ScanDiffReport if a baseline exists.

    Findings are matched by evidence_hash (title + url + evidence[:200] SHA-256).
    """
    from apps.scans.models import ScanDiffReport
    from apps.results.models import Finding

    try:
        # Find the most recent prior completed job for same module+project
        prev_job = (
            ScanJob.objects
            .filter(
                module_id=current_job.module_id,
                project=current_job.project,
                status=ScanJob.Status.DONE,
            )
            .exclude(id=current_job.id)
            .order_by("-finished_at")
            .first()
        )
        if not prev_job:
            return  # No baseline to compare against

        baseline_hashes = set(
            Finding.objects.filter(scan_job=prev_job)
            .values_list("evidence_hash", flat=True)
        )
        current_hashes = {
            f.evidence_hash
            for f in Finding.objects.filter(scan_job=current_job)
        }

        new_hashes      = current_hashes - baseline_hashes
        resolved_hashes = baseline_hashes - current_hashes
        unchanged_count = len(current_hashes & baseline_hashes)

        new_findings = list(
            Finding.objects.filter(scan_job=current_job, evidence_hash__in=new_hashes)
            .values("title", "severity", "url", "description", "cve_id")[:500]
        )
        resolved_findings = list(
            Finding.objects.filter(scan_job=prev_job, evidence_hash__in=resolved_hashes)
            .values("title", "severity", "url")[:500]
        )

        ScanDiffReport.objects.create(
            module_id=current_job.module_id,
            baseline_job=prev_job,
            current_job=current_job,
            project=current_job.project,
            new_count=len(new_hashes),
            resolved_count=len(resolved_hashes),
            unchanged_count=unchanged_count,
            new_critical=sum(1 for f in new_findings if f.get("severity") == "critical"),
            new_high=sum(1 for f in new_findings if f.get("severity") == "high"),
            diff_data={
                "new": new_findings,
                "resolved": resolved_findings,
            },
        )
    except Exception:
        pass  # Diff report is non-critical; never crash the main task


# ─── Scan Chain Dispatcher ────────────────────────────────────────────────────

def _trigger_scan_chains(parent_job, metadata: dict, task_self):
    """
    After a job completes, look up active ScanChain rules for the parent module
    and dispatch child jobs accordingly.

    The param_mapping supports two modes:
      - Single target:  {"target_param": "target_url", "source_key": "metadata.subdomains[0]"}
      - Expand list:    {"expand": true, "list_key": "subdomains", "target_param": "target_url",
                          "prefix": "https://"}
        → Creates one child ScanJob per item in the list (capped at 50).
    """
    from apps.scans.models import ScanChain

    chains = ScanChain.objects.filter(parent_module=parent_job.module_id, is_active=True)
    if not chains.exists():
        return

    for chain in chains:
        try:
            mapping = chain.param_mapping or {}
            base_params = dict(chain.base_params or {})

            if mapping.get("expand") and mapping.get("list_key"):
                # One child job per item in a metadata list
                items = metadata.get(mapping["list_key"], [])
                if not items:
                    continue
                prefix  = mapping.get("prefix", "")
                tgt_key = mapping.get("target_param", "target_url")
                cap     = min(len(items), 50)  # cap at 50 to avoid explosion

                task_self.stream(
                    str(parent_job.id), "info",
                    f"[chain] Spawning {cap} {chain.child_module} jobs from {chain.name}..."
                )

                for item in items[:cap]:
                    child_params = dict(base_params)
                    child_params[tgt_key] = f"{prefix}{item}"
                    _dispatch_child_job(chain, child_params, parent_job)

            else:
                # Single child job — simple key extraction from metadata
                child_params = dict(base_params)
                if mapping.get("target_param") and mapping.get("source_key"):
                    val = metadata.get(mapping["source_key"])
                    if val:
                        child_params[mapping["target_param"]] = val
                _dispatch_child_job(chain, child_params, parent_job)

        except Exception:
            pass  # Chain errors are non-critical


def _dispatch_child_job(chain, child_params: dict, parent_job):
    """Create a ScanJob and enqueue it on the appropriate Celery queue."""
    from apps.modules.engine import ModuleRegistry

    registry = ModuleRegistry.instance()
    module = registry.get(chain.child_module)
    if module is None:
        return

    child_job = ScanJob.objects.create(
        module_id=chain.child_module,
        params=child_params,
        created_by=parent_job.created_by,
        project=parent_job.project,
        target=parent_job.target,
        status=ScanJob.Status.PENDING,
    )

    execute_module.apply_async(
        args=[str(child_job.id)],
        queue=module.celery_queue,
        priority=5,
    )


# ─── Scheduled Scan Runner ────────────────────────────────────────────────────

@shared_task(name="scans.execute_scheduled_scan")
def execute_scheduled_scan(scheduled_scan_id: str):
    """
    Called by celery-beat for recurring scans.
    Creates a fresh ScanJob from the ScheduledScan template and dispatches it.
    """
    from apps.scans.models import ScheduledScan
    from apps.modules.engine import ModuleRegistry

    try:
        scheduled = ScheduledScan.objects.get(id=scheduled_scan_id, is_active=True)
    except ScheduledScan.DoesNotExist:
        return

    registry = ModuleRegistry.instance()
    module = registry.get(scheduled.module_id)
    if module is None:
        return

    job = ScanJob.objects.create(
        module_id=scheduled.module_id,
        params=scheduled.params,
        created_by=scheduled.created_by,
        project=scheduled.project,
        target=scheduled.target,
        status=ScanJob.Status.PENDING,
    )

    execute_module.apply_async(
        args=[str(job.id)],
        queue=module.celery_queue,
        priority=4,  # Lower priority than manual scans
    )

    scheduled.last_run_at = dj_tz.now()
    scheduled.run_count   = (scheduled.run_count or 0) + 1
    scheduled.save(update_fields=["last_run_at", "run_count"])
