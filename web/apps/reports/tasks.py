"""
Celery tasks for async report generation.
"""
from celery import shared_task
from django.utils import timezone


@shared_task(bind=True, max_retries=2)
def generate_report_task(self, report_id: str, fmt: str):
    """
    Generate a report in the specified format and store result.
    fmt: 'html' | 'pdf' | 'json' | 'markdown'
    """
    from apps.reports.models import Report

    try:
        report = Report.objects.get(pk=report_id)
    except Report.DoesNotExist:
        return

    report.status = "generating"
    report.celery_task_id = self.request.id
    report.save(update_fields=["status", "celery_task_id"])

    try:
        from apps.reports.generators import (
            generate_html, generate_pdf, generate_json, generate_markdown
        )

        if fmt == "pdf":
            content = generate_pdf(report)
        elif fmt == "json":
            content = generate_json(report)
        elif fmt == "markdown":
            content = generate_markdown(report).encode("utf-8")
        else:
            content = generate_html(report).encode("utf-8")

        # Store in media / temp file
        import os
        from django.conf import settings as djsettings

        out_dir = os.path.join(djsettings.MEDIA_ROOT, "reports", str(report_id))
        os.makedirs(out_dir, exist_ok=True)
        ext_map = {"pdf": "pdf", "json": "json", "markdown": "md", "html": "html"}
        ext = ext_map.get(fmt, "html")
        out_path = os.path.join(out_dir, f"report.{ext}")

        mode = "wb" if isinstance(content, bytes) else "w"
        with open(out_path, mode) as fh:
            fh.write(content)

        report.status = "ready"
        report.last_format = fmt
        report.generated_at = timezone.now()
        report.save(update_fields=["status", "last_format", "generated_at"])

    except Exception as exc:
        report.status = "failed"
        report.save(update_fields=["status"])
        raise self.retry(exc=exc, countdown=30)


@shared_task
def notify_new_finding(finding_id: str):
    """
    Dispatch notifications for a new critical/high finding.
    Called by results.models signal after Finding creation.
    """
    from apps.results.models import Finding
    from apps.notifications.dispatcher import dispatch_finding_alert

    try:
        finding = Finding.objects.select_related("project").get(pk=finding_id)
        if finding.severity in ("critical", "high"):
            dispatch_finding_alert(finding)
    except Finding.DoesNotExist:
        pass
