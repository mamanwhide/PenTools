"""
Report model — represents a generated pentest report for a project.
"""
from __future__ import annotations
import uuid
from django.db import models
from django.conf import settings


class Report(models.Model):
    class Status(models.TextChoices):
        DRAFT      = "draft",      "Draft"
        GENERATING = "generating", "Generating"
        READY      = "ready",      "Ready"
        FAILED     = "failed",     "Failed"

    class Format(models.TextChoices):
        HTML     = "html",     "HTML"
        PDF      = "pdf",      "PDF"
        JSON     = "json",     "JSON"
        MARKDOWN = "markdown", "Markdown"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        "targets.Project", on_delete=models.CASCADE, related_name="reports"
    )
    title = models.CharField(max_length=300, default="Penetration Test Report")
    executive_summary = models.TextField(blank=True)

    # Builder: ordered list of finding UUIDs chosen by user
    finding_ids = models.JSONField(
        default=list,
        blank=True,
        help_text="Ordered list of Finding UUIDs to include. Empty = all project findings.",
    )

    # Branding
    logo_base64 = models.TextField(blank=True, help_text="Base64 PNG/SVG logo")
    company_name = models.CharField(max_length=200, blank=True)
    assessor_name = models.CharField(max_length=200, blank=True)
    report_date = models.DateField(null=True, blank=True)

    # Engagement metadata
    engagement_type = models.CharField(
        max_length=20,
        choices=[
            ("black-box", "Black-Box"),
            ("grey-box",  "Grey-Box"),
            ("white-box", "White-Box"),
            ("hybrid",    "Hybrid"),
        ],
        default="black-box",
    )
    methodology_notes = models.TextField(
        blank=True,
        help_text="Testing approach & methodology description (appended to Section 2)",
    )
    scope_notes = models.TextField(
        blank=True,
        help_text="Additional Scope of Work context (appended to Section 3)",
    )

    # Options
    include_graph_png = models.BooleanField(default=False)
    include_evidence = models.BooleanField(default=True)
    include_remediation = models.BooleanField(default=True)
    min_severity = models.CharField(
        max_length=20, default="info",
        choices=[
            ("critical", "Critical only"),
            ("high",     "High and above"),
            ("medium",   "Medium and above"),
            ("low",      "Low and above"),
            ("info",     "All"),
        ],
    )

    # Scope: which targets to include (empty = all targets in the project)
    targets = models.ManyToManyField(
        "targets.Target",
        blank=True,
        related_name="reports",
        help_text="Targets to include in this report. Leave empty to include all project targets.",
    )

    # Generation
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.DRAFT)
    last_format = models.CharField(max_length=20, choices=Format.choices, blank=True)
    generated_at = models.DateTimeField(null=True, blank=True)
    celery_task_id = models.CharField(max_length=255, blank=True)

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True,
        related_name="reports"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.title} — {self.project}"
