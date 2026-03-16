"""
Notification channel configuration models — Telegram, Slack, Email.
"""
from __future__ import annotations
import uuid
from django.db import models
from django.conf import settings


class NotificationChannel(models.Model):
    """A configured notification channel for a project or globally for a user."""

    class ChannelType(models.TextChoices):
        TELEGRAM = "telegram", "Telegram Bot"
        SLACK    = "slack",    "Slack Webhook"
        EMAIL    = "email",    "Email SMTP"

    class TriggerEvent(models.TextChoices):
        FINDING_CRITICAL = "finding_critical", "New Critical Finding"
        FINDING_HIGH     = "finding_high",     "New High Finding"
        SCAN_COMPLETE    = "scan_complete",     "Scan Complete"
        REPORT_READY     = "report_ready",      "Report Ready"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, help_text="Friendly label, e.g. 'Security Team Slack'")
    channel_type = models.CharField(max_length=20, choices=ChannelType.choices)

    # Scoping: per-project or user-global (project=None)
    project = models.ForeignKey(
        "targets.Project",
        on_delete=models.CASCADE,
        related_name="notification_channels",
        null=True,
        blank=True,
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notification_channels",
    )

    is_active = models.BooleanField(default=True)

    # Telegram
    telegram_bot_token = models.CharField(max_length=200, blank=True)
    telegram_chat_id = models.CharField(max_length=100, blank=True)

    # Slack
    slack_webhook_url = models.URLField(max_length=500, blank=True)

    # Email SMTP
    smtp_host = models.CharField(max_length=200, blank=True)
    smtp_port = models.PositiveSmallIntegerField(default=587)
    smtp_use_tls = models.BooleanField(default=True)
    smtp_username = models.CharField(max_length=200, blank=True)
    smtp_password = models.CharField(max_length=500, blank=True)  # stored encrypted at app layer
    email_from = models.EmailField(blank=True)
    email_to = models.TextField(
        blank=True,
        help_text="Comma-separated recipient email addresses",
    )

    # Events this channel listens for
    trigger_events = models.JSONField(
        default=list,
        help_text="List of TriggerEvent values",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name} ({self.channel_type})"


class NotificationLog(models.Model):
    """Record of every dispatched notification."""

    class Result(models.TextChoices):
        SENT   = "sent",   "Sent"
        FAILED = "failed", "Failed"
        SKIP   = "skip",   "Skipped (inactive)"

    id = models.BigAutoField(primary_key=True)
    channel = models.ForeignKey(
        NotificationChannel, on_delete=models.CASCADE, related_name="logs"
    )
    event = models.CharField(max_length=50)
    payload_preview = models.TextField(blank=True)
    result = models.CharField(max_length=10, choices=Result.choices, default=Result.SENT)
    error = models.TextField(blank=True)
    sent_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-sent_at"]

    def __str__(self):
        return f"{self.channel} — {self.event} — {self.result}"
