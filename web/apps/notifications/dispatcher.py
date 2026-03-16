"""
Notification dispatcher — sends alerts via Telegram, Slack, and Email.
Called from Celery tasks (async).
"""
from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


# ─── Main dispatch entrypoint ─────────────────────────────────────────────────

def dispatch_finding_alert(finding):
    """
    Send notifications for a new finding to all matching active channels.
    Matches channels on project and severity trigger events.
    """
    from .models import NotificationChannel, NotificationLog

    event = (
        "finding_critical" if finding.severity == "critical"
        else "finding_high"
    )

    channels = NotificationChannel.objects.filter(
        is_active=True,
    ).filter(
        # Project-specific OR global (project=None) channels owned by finding.project.owner
        models.Q(project=finding.project) |
        models.Q(project__isnull=True, owner=finding.project.owner if finding.project else None)
    )

    for ch in channels:
        if event not in (ch.trigger_events or []):
            continue
        _dispatch_channel(ch, event, finding)


def dispatch_scan_complete(scan_job):
    """Send scan_complete notification."""
    from .models import NotificationChannel

    channels = NotificationChannel.objects.filter(
        is_active=True,
    ).filter(
        models.Q(project=scan_job.project) |
        models.Q(project__isnull=True, owner=scan_job.created_by)
    )
    for ch in channels:
        if "scan_complete" not in (ch.trigger_events or []):
            continue
        _dispatch_channel(ch, "scan_complete", scan_job)


def dispatch_report_ready(report):
    """Send report_ready notification."""
    from .models import NotificationChannel

    channels = NotificationChannel.objects.filter(
        is_active=True,
        project=report.project,
    )
    for ch in channels:
        if "report_ready" not in (ch.trigger_events or []):
            continue
        _dispatch_channel(ch, "report_ready", report)


# ─── Per-channel dispatch ─────────────────────────────────────────────────────

def _dispatch_channel(channel, event: str, obj):
    from .models import NotificationLog
    try:
        if channel.channel_type == "telegram":
            _send_telegram(channel, event, obj)
        elif channel.channel_type == "slack":
            _send_slack(channel, event, obj)
        elif channel.channel_type == "email":
            _send_email(channel, event, obj)
        else:
            return

        NotificationLog.objects.create(
            channel=channel,
            event=event,
            payload_preview=_preview(obj)[:500],
            result="sent",
        )
    except Exception as exc:
        logger.error("Notification dispatch failed: %s — %s", channel, exc)
        NotificationLog.objects.create(
            channel=channel,
            event=event,
            payload_preview=_preview(obj)[:500],
            result="failed",
            error=str(exc)[:1000],
        )


# ─── Telegram ─────────────────────────────────────────────────────────────────

def _send_telegram(channel, event: str, obj):
    import requests as req

    text = _format_message(event, obj, "markdown")
    token = channel.telegram_bot_token
    chat_id = channel.telegram_chat_id
    if not token or not chat_id:
        raise ValueError("Telegram: missing bot_token or chat_id")

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    resp = req.post(url, json={
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "MarkdownV2",
        "disable_web_page_preview": True,
    }, timeout=15)
    if not resp.ok:
        raise RuntimeError(f"Telegram API error {resp.status_code}: {resp.text[:200]}")


# ─── Slack ────────────────────────────────────────────────────────────────────

def _send_slack(channel, event: str, obj):
    import requests as req

    webhook = channel.slack_webhook_url
    if not webhook:
        raise ValueError("Slack: missing webhook_url")

    text = _format_message(event, obj, "plain")
    payload = {
        "text": text,
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": _format_message(event, obj, "slack")}},
        ],
    }
    resp = req.post(webhook, json=payload, timeout=15)
    if not resp.ok and resp.text != "ok":
        raise RuntimeError(f"Slack webhook error: {resp.text[:200]}")


# ─── Email ────────────────────────────────────────────────────────────────────

def _send_email(channel, event: str, obj):
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText

    if not channel.smtp_host or not channel.email_to:
        raise ValueError("Email: missing smtp_host or email_to")

    recipients = [r.strip() for r in channel.email_to.split(",") if r.strip()]
    subject = _email_subject(event, obj)
    body_html = _format_message(event, obj, "html")
    body_text = _format_message(event, obj, "plain")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = channel.email_from or channel.smtp_username
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(body_text, "plain"))
    msg.attach(MIMEText(body_html, "html"))

    with smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=30) as smtp:
        if channel.smtp_use_tls:
            smtp.starttls()
        if channel.smtp_username and channel.smtp_password:
            smtp.login(channel.smtp_username, channel.smtp_password)
        smtp.sendmail(msg["From"], recipients, msg.as_string())


# ─── Message formatting ───────────────────────────────────────────────────────

def _preview(obj) -> str:
    try:
        return str(obj)
    except Exception:
        return ""


def _email_subject(event: str, obj) -> str:
    from apps.results.models import Finding
    from apps.scans.models import ScanJob

    if isinstance(obj, Finding):
        return f"[PenTools] {obj.severity.upper()} Finding: {obj.title[:60]}"
    if isinstance(obj, ScanJob):
        return f"[PenTools] Scan Complete: {obj.module_id} — {obj.status}"
    return f"[PenTools] {event}"


def _format_message(event: str, obj, fmt: str) -> str:
    from apps.results.models import Finding
    from apps.scans.models import ScanJob

    SEV_EMOJI = {
        "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"
    }

    if isinstance(obj, Finding):
        icon = SEV_EMOJI.get(obj.severity, "⚪")
        if fmt == "slack":
            return (
                f"{icon} *{obj.severity.upper()} Finding*\n"
                f"*{obj.title}*\n"
                f"URL: `{obj.url or 'N/A'}`\n"
                f"CWE: {obj.cwe_id or 'N/A'} | CVE: {obj.cve_id or 'N/A'}\n"
                f"_{obj.description[:200] if obj.description else ''}_"
            )
        elif fmt == "markdown":
            # Telegram MarkdownV2 — escape special chars
            def esc(s):
                for c in r"_*[]()~`>#+-=|{}.!":
                    s = s.replace(c, f"\\{c}")
                return s
            return (
                f"{icon} *{esc(obj.severity.upper())} Finding*\n"
                f"*{esc(obj.title[:100])}*\n"
                f"URL: `{esc(obj.url or 'N/A')}`\n"
                f"CWE: {esc(obj.cwe_id or 'N/A')}"
            )
        elif fmt == "html":
            return (
                f"<h3>{icon} {obj.severity.upper()} Finding: {obj.title}</h3>"
                f"<p><b>URL:</b> {obj.url or 'N/A'}</p>"
                f"<p><b>Description:</b> {obj.description[:500] or 'N/A'}</p>"
                f"<p><b>CWE:</b> {obj.cwe_id or 'N/A'} &bull; <b>CVE:</b> {obj.cve_id or 'N/A'}</p>"
            )
        else:
            return (
                f"{icon} {obj.severity.upper()} FINDING\n"
                f"Title: {obj.title}\n"
                f"URL: {obj.url or 'N/A'}\n"
                f"CWE: {obj.cwe_id or 'N/A'}"
            )

    if isinstance(obj, ScanJob):
        if fmt == "slack":
            return (
                f"✅ *Scan Complete*\n"
                f"Module: `{obj.module_id}` — Status: `{obj.status}`\n"
                f"Findings: {obj.finding_count} | Critical: {obj.critical_count} | High: {obj.high_count}"
            )
        elif fmt == "html":
            return (
                f"<h3>✅ Scan Complete: {obj.module_id}</h3>"
                f"<p>Status: {obj.status} | Findings: {obj.finding_count}</p>"
            )
        else:
            return (
                f"Scan Complete: {obj.module_id} — {obj.status}\n"
                f"Findings: {obj.finding_count}"
            )

    return f"[PenTools] {event}: {str(obj)[:200]}"


# needed for Q objects in module scope
from django.db import models
