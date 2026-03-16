import uuid
from django.db import models
from django.conf import settings


class ScanJob(models.Model):
    """Represents a single module execution triggered by a user."""

    class Status(models.TextChoices):
        PENDING   = "pending",   "Pending"
        RUNNING   = "running",   "Running"
        PAUSED    = "paused",    "Paused"
        DONE      = "done",      "Done"
        FAILED    = "failed",    "Failed"
        CANCELLED = "cancelled", "Cancelled"

    id          = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    module_id   = models.CharField(max_length=100, db_index=True)
    # Params stored as JSON. Sensitive values encrypted at app layer.
    params      = models.JSONField(default=dict)
    status      = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING, db_index=True)
    progress    = models.PositiveSmallIntegerField(default=0)   # 0–100
    celery_task_id = models.CharField(max_length=255, blank=True)
    created_by  = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="scan_jobs")
    target      = models.ForeignKey("targets.Target", null=True, blank=True, on_delete=models.SET_NULL, related_name="scan_jobs")
    project     = models.ForeignKey("targets.Project", null=True, blank=True, on_delete=models.SET_NULL, related_name="scan_jobs")
    created_at  = models.DateTimeField(auto_now_add=True)
    started_at  = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    # Summary stats populated after completion
    finding_count     = models.PositiveIntegerField(default=0)
    critical_count    = models.PositiveIntegerField(default=0)
    high_count        = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["-created_at"]
        db_table = "scans_scanjob"

    def __str__(self):
        return f"[{self.module_id}] {self.id} — {self.status}"

    @property
    def duration_seconds(self):
        if self.started_at and self.finished_at:
            return int((self.finished_at - self.started_at).total_seconds())
        return None


class ScanLog(models.Model):
    """Individual log line streamed during a ScanJob execution."""

    class Level(models.TextChoices):
        INFO    = "info",    "Info"
        SUCCESS = "success", "Success"
        WARNING = "warning", "Warning"
        ERROR   = "error",   "Error"

    id        = models.BigAutoField(primary_key=True)
    scan_job  = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="logs")
    level     = models.CharField(max_length=10, choices=Level.choices, default=Level.INFO)
    message   = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["timestamp"]
        db_table = "scans_scanlog"


class ScanJobTemplate(models.Model):
    """Named parameter preset saved by a user for a specific module."""

    id         = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    module_id  = models.CharField(max_length=100, db_index=True)
    name       = models.CharField(max_length=200)
    params     = models.JSONField(default=dict)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scan_templates",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        db_table = "scans_scanjobtemplate"
        unique_together = [("module_id", "name", "created_by")]

    def __str__(self):
        return f"{self.module_id}/{self.name}"


# ─── Scan Chaining ────────────────────────────────────────────────────────────

class ScanChain(models.Model):
    """
    Defines an automatic downstream scan that fires when a parent module completes.

    Example: R-02 (subdomain enum) finishes → V-01 (nuclei) auto-starts on each
    discovered HTTP endpoint, and R-01 (port scan) runs on each discovered IP.

    The 'param_mapping' JSON defines how to extract outputs from the parent job
    and inject them as params into the child job.

    Example param_mapping for R-02 → V-01:
        {
            "source": "metadata.subdomains[0]",   ← take first subdomain
            "target_param": "target_url",
            "prefix": "https://"
        }

    For chaining to multiple targets (one child job per subdomain), set
    'expand_list': true with 'source_list' pointing to a list in metadata.
    """

    class TriggerOn(models.TextChoices):
        DONE    = "done",    "On Success"
        ALWAYS  = "always",  "Always (success or failure)"

    id             = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name           = models.CharField(max_length=200)
    parent_module  = models.CharField(max_length=100, db_index=True,
                                       help_text="Module ID of the trigger module, e.g. 'R-02'")
    child_module   = models.CharField(max_length=100,
                                       help_text="Module ID to launch downstream, e.g. 'V-01'")
    trigger_on     = models.CharField(max_length=10, choices=TriggerOn.choices, default=TriggerOn.DONE)
    param_mapping  = models.JSONField(default=dict,
                                       help_text="How to map parent outputs → child params")
    base_params    = models.JSONField(default=dict,
                                       help_text="Fixed params always sent to child (merged with mapped params)")
    is_active      = models.BooleanField(default=True)
    created_by     = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                        related_name="scan_chains")
    created_at     = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["parent_module", "child_module"]
        db_table = "scans_scanchain"

    def __str__(self):
        return f"{self.parent_module} → {self.child_module} ({self.name})"


# ─── Scheduled Recurring Scans ────────────────────────────────────────────────

class ScheduledScan(models.Model):
    """
    A recurring scan template.  celery-beat fires execute_scheduled_scan() on the
    cron schedule, which creates a fresh ScanJob and dispatches it.
    """

    class Schedule(models.TextChoices):
        HOURLY   = "hourly",   "Every hour"
        DAILY    = "daily",    "Daily"
        WEEKLY   = "weekly",   "Weekly"
        BIWEEKLY = "biweekly", "Every 2 weeks"
        MONTHLY  = "monthly",  "Monthly"

    id         = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name       = models.CharField(max_length=200)
    module_id  = models.CharField(max_length=100, db_index=True)
    params     = models.JSONField(default=dict)
    schedule   = models.CharField(max_length=20, choices=Schedule.choices, default=Schedule.DAILY)
    is_active  = models.BooleanField(default=True)
    # FK to django-celery-beat PeriodicTask so we can manage it there too
    periodic_task_name = models.CharField(max_length=200, blank=True, db_index=True)
    project    = models.ForeignKey("targets.Project", null=True, blank=True,
                                    on_delete=models.SET_NULL, related_name="scheduled_scans")
    target     = models.ForeignKey("targets.Target", null=True, blank=True,
                                    on_delete=models.SET_NULL, related_name="scheduled_scans")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE,
                                    related_name="scheduled_scans")
    last_run_at  = models.DateTimeField(null=True, blank=True)
    next_run_at  = models.DateTimeField(null=True, blank=True)
    run_count    = models.PositiveIntegerField(default=0)
    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        db_table = "scans_scheduledscan"

    def __str__(self):
        return f"{self.name} [{self.module_id}] ({self.schedule})"

    def celery_crontab(self):
        """Return a kombu crontab for this schedule."""
        from celery.schedules import crontab
        return {
            "hourly":   crontab(minute=0),
            "daily":    crontab(hour=3, minute=0),
            "weekly":   crontab(day_of_week=1, hour=3, minute=0),
            "biweekly": crontab(day_of_week=1, hour=3, minute=0, day_of_month="1-14"),
            "monthly":  crontab(day_of_month=1, hour=3, minute=0),
        }.get(self.schedule, crontab(hour=3, minute=0))


# ─── Diff Reporting ───────────────────────────────────────────────────────────

class ScanDiffReport(models.Model):
    """
    Stores the diff between two ScanJob runs of the same module+target.
    Generated automatically after each scan completes if a previous run exists.
    """

    id           = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    module_id    = models.CharField(max_length=100, db_index=True)
    baseline_job = models.ForeignKey(ScanJob, on_delete=models.CASCADE,
                                      related_name="diff_as_baseline")
    current_job  = models.ForeignKey(ScanJob, on_delete=models.CASCADE,
                                      related_name="diff_as_current")
    project      = models.ForeignKey("targets.Project", null=True, blank=True,
                                      on_delete=models.SET_NULL, related_name="diff_reports")

    # Summary counts
    new_count        = models.PositiveIntegerField(default=0)
    resolved_count   = models.PositiveIntegerField(default=0)
    unchanged_count  = models.PositiveIntegerField(default=0)
    new_critical     = models.PositiveIntegerField(default=0)
    new_high         = models.PositiveIntegerField(default=0)

    # Detailed JSON payload  { "new": [...], "resolved": [...], "unchanged": [...] }
    diff_data    = models.JSONField(default=dict)
    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        db_table = "scans_scandiffreport"
        indexes = [models.Index(fields=["module_id", "project"])]

    def __str__(self):
        return f"Diff {self.module_id}: +{self.new_count} -{self.resolved_count} (job {self.current_job_id})"
