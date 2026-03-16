from django.db import models
from django.conf import settings
from django.utils import timezone
import uuid
import hashlib


class Finding(models.Model):
    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFO = "info", "Info"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        CONFIRMED = "confirmed", "Confirmed"
        MITIGATED = "mitigated", "Mitigated"
        CLOSED = "closed", "Closed"
        FALSE_POSITIVE = "fp", "False Positive"
        FIXED = "fixed", "Fixed"
        WONT_FIX = "wontfix", "Won't Fix"

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_job = models.ForeignKey(
        "scans.ScanJob",
        on_delete=models.CASCADE,
        related_name="findings",
        null=True,
        blank=True,
    )
    # project link (for manual findings not tied to a scan_job)
    project = models.ForeignKey(
        "targets.Project",
        on_delete=models.CASCADE,
        related_name="findings",
        null=True,
        blank=True,
    )
    title = models.CharField(max_length=500)
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.INFO)
    url = models.TextField(blank=True)
    description = models.TextField(blank=True)
    evidence = models.TextField(blank=True)
    # SHA-256 of (title + url + evidence[:200]) for duplicate detection
    evidence_hash = models.CharField(max_length=64, blank=True, db_index=True)
    remediation = models.TextField(blank=True)
    cvss_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
    cvss_vector = models.CharField(max_length=200, blank=True)
    cve_id = models.CharField(max_length=50, blank=True)
    cwe_id = models.CharField(max_length=30, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    is_manual = models.BooleanField(default=False, help_text="True if entered manually by user")
    raw_data = models.JSONField(default=dict, blank=True)
    notes = models.TextField(blank=True)
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_findings",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_findings",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["scan_job", "severity"]),
            models.Index(fields=["project", "severity"]),
            models.Index(fields=["status"]),
            models.Index(fields=["evidence_hash"]),
        ]

    def __str__(self):
        return f"[{self.severity.upper()}] {self.title}"

    def compute_hash(self):
        raw = f"{self.title}|{self.url}|{self.evidence[:200]}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def save(self, *args, **kwargs):
        # Auto-populate project from scan_job if not set
        if self.scan_job and not self.project_id:
            self.project = self.scan_job.project
        # Compute evidence hash for dedup
        self.evidence_hash = self.compute_hash()
        super().save(*args, **kwargs)

    @property
    def is_duplicate(self):
        """True if another Finding with same hash exists in the same project."""
        qs = Finding.objects.filter(evidence_hash=self.evidence_hash)
        if self.project_id:
            qs = qs.filter(project=self.project)
        return qs.exclude(pk=self.pk).exists()

    @property
    def severity_color(self):
        colors = {
            "critical": "text-red-500",
            "high": "text-orange-500",
            "medium": "text-yellow-500",
            "low": "text-blue-400",
            "info": "text-gray-400",
        }
        return colors.get(self.severity, "text-gray-400")

    @property
    def severity_badge_class(self):
        badges = {
            "critical": "bg-red-500/20 text-red-400 border border-red-500/30",
            "high":     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
            "medium":   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
            "low":      "bg-blue-500/20 text-blue-400 border border-blue-500/30",
            "info":     "bg-gray-500/20 text-gray-400 border border-gray-500/30",
        }
        return badges.get(self.severity, badges["info"])


class FindingStatusHistory(models.Model):
    """Audit trail for Finding status transitions."""
    id = models.BigAutoField(primary_key=True)
    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="status_history")
    from_status = models.CharField(max_length=20, blank=True)
    to_status = models.CharField(max_length=20)
    changed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True
    )
    note = models.TextField(blank=True)
    changed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["changed_at"]

    def __str__(self):
        return f"{self.finding} | {self.from_status} → {self.to_status}"
