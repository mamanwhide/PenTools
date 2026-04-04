"""
PenTools Telegram Bot — command dispatcher.

Commands:
  /start               — Welcome message + auth instructions
  /auth <api_key>      — Link this Telegram chat to a PenTools user account
  /me                  — Show linked account info
  /projects            — List your projects
  /modules [category]  — Browse modules (optional category filter)
  /scan <ID> <URL>     — Launch a scan against a target URL
  /recent              — Your 5 most recent scans
  /status <job_id>     — Check scan status (first 8 chars of UUID accepted)
  /findings <job_id>   — Findings summary for a scan
  /cancel  <job_id>    — Cancel a pending / running scan
  /help                — Full command list
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Telegram helpers ──────────────────────────────────────────────────────────

def get_bot_token() -> str:
    from django.conf import settings
    return getattr(settings, "TELEGRAM_BOT_TOKEN", "") or ""


def send_message(chat_id: str, text: str, parse_mode: str = "HTML") -> bool:
    import requests
    token = get_bot_token()
    if not token:
        return False
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            },
            timeout=10,
        )
        if not resp.ok:
            logger.warning("Telegram sendMessage %s: %s", resp.status_code, resp.text[:200])
        return resp.ok
    except Exception as exc:
        logger.error("Telegram sendMessage exception: %s", exc)
        return False


# ── Update dispatcher ─────────────────────────────────────────────────────────

def handle_update(update: dict) -> None:
    """Process a single Telegram Update object."""
    msg = update.get("message") or update.get("edited_message")
    if not msg:
        return

    chat_id = str(msg["chat"]["id"])
    text = (msg.get("text") or "").strip()

    if not text.startswith("/"):
        return

    parts = text.split(None, 2)
    # Strip @botname suffix (e.g. /scan@pento0lsbot)
    command = parts[0].split("@")[0].lower()
    args = parts[1:] if len(parts) > 1 else []

    HANDLERS = {
        "/start":    _cmd_start,
        "/help":     _cmd_help,
        "/auth":     _cmd_auth,
        "/me":       _cmd_me,
        "/projects": _cmd_projects,
        "/modules":  _cmd_modules,
        "/scan":     _cmd_scan,
        "/recent":   _cmd_recent,
        "/status":   _cmd_status,
        "/findings": _cmd_findings,
        "/cancel":   _cmd_cancel,
    }

    fn = HANDLERS.get(command)
    if fn:
        try:
            fn(args, chat_id)
        except Exception as exc:
            logger.error("Bot command error [%s %s]: %s", command, args, exc, exc_info=True)
            send_message(chat_id, "/0\\ An error occurred. Please try again or use /help.")
    else:
        send_message(chat_id, f"Unknown command: <code>{command}</code>\nUse /help for the full list.")


# ── Auth helpers ──────────────────────────────────────────────────────────────

def _get_session(chat_id: str):
    from .models import TelegramBotSession
    return TelegramBotSession.objects.select_related("user").filter(chat_id=chat_id).first()


def _require_auth(chat_id: str):
    """Return session if authenticated, else send auth prompt and return None."""
    session = _get_session(chat_id)
    if not session:
        send_message(
            chat_id,
            "/0\\<b>Authentication required</b>\n\n"
            "Link your PenTools account first:\n"
            "<code>/auth YOUR_API_KEY</code>\n\n"
            "Get your API key from your PenTools profile page.",
        )
    return session


# ── Command handlers ──────────────────────────────────────────────────────────

def _cmd_start(args, chat_id):
    send_message(
        chat_id,
        "/0\\ <b>Welcome to PenTools Bot!</b>\n\n"
        "Launch and monitor penetration test scans directly from Telegram.\n\n"
        "<b>Get started:</b>\n"
        "1. Log into PenTools and open your profile\n"
        "2. Copy your API key\n"
        "3. Send: <code>/auth YOUR_API_KEY</code>\n\n"
        "Then use /help to see all available commands.",
    )


def _cmd_help(args, chat_id):
    send_message(
        chat_id,
        "/0\\ <b>PenTools Bot — Commands</b>\n\n"
        "/auth <code>API_KEY</code>         — Link your account\n"
        "/me                        — Show linked account\n"
        "/projects                  — List your projects\n"
        "/modules [<code>category</code>]   — Browse modules\n"
        "/scan <code>MOD_ID URL</code>      — Launch a scan\n"
        "  e.g. <code>/scan V-01 https://example.com</code>\n"
        "/recent                    — 5 most recent scans\n"
        "/status <code>JOB_ID</code>        — Scan status\n"
        "/findings <code>JOB_ID</code>      — Findings summary\n"
        "/cancel <code>JOB_ID</code>        — Cancel a scan\n\n"
        "/0\\ <b>JOB_ID</b> can be the first 8 characters of the full UUID.",
    )


def _cmd_auth(args, chat_id):
    if not args:
        send_message(chat_id, "Usage: /auth <code>YOUR_API_KEY</code>")
        return

    api_key = args[0].strip()

    try:
        from apps.accounts.models import User
        user = User.objects.filter(api_key=api_key).first()
    except Exception:
        user = None

    if not user:
        send_message(
            chat_id,
            "/x\\ Invalid API key.\n"
            "Get yours from the PenTools profile page (<b>Profile → API Key</b>).",
        )
        return

    from .models import TelegramBotSession
    _, created = TelegramBotSession.objects.update_or_create(
        chat_id=chat_id,
        defaults={"user": user},
    )
    action = "linked" if created else "updated"
    send_message(
        chat_id,
        f"/y\\ <b>Account {action}!</b>\n\n"
        f"Logged in as: <b>{user.username}</b> ({user.email})\n\n"
        "Use /help to see what you can do.\n"
        "Try: /projects — /modules — /scan V-01 https://example.com",
    )


def _cmd_me(args, chat_id):
    session = _require_auth(chat_id)
    if not session:
        return
    u = session.user
    role = getattr(u, "role", "—")
    send_message(
        chat_id,
        f"/0\\ 👤 <b>{u.username}</b>\n"
        f"Email: {u.email}\n"
        f"Role: {role}\n"
        f"Last seen: {session.last_seen.strftime('%Y-%m-%d %H:%M UTC')}",
    )


def _cmd_projects(args, chat_id):
    session = _require_auth(chat_id)
    if not session:
        return

    from apps.targets.models import Project
    from django.db.models import Q

    projects = (
        Project.objects.filter(Q(owner=session.user) | Q(members=session.user))
        .distinct()
        .order_by("-created_at")[:10]
    )

    if not projects:
        send_message(chat_id, "No projects found. Create one in the web UI.")
        return

    lines = ["/0\\ <b>Your Projects:</b>\n"]
    for p in projects:
        lines.append(f"• <b>{p.name}</b>  <code>{str(p.id)[:8]}</code>")
    send_message(chat_id, "\n".join(lines))


def _cmd_modules(args, chat_id):
    session = _require_auth(chat_id)
    if not session:
        return

    from apps.modules.engine import ModuleRegistry
    from collections import defaultdict

    registry = ModuleRegistry.instance()
    all_mods = list(registry.all())

    category_filter = args[0].lower() if args else None
    if category_filter:
        all_mods = [m for m in all_mods if category_filter in m.category.lower()]

    if not all_mods:
        send_message(chat_id, f"No modules found for category '<code>{category_filter}</code>'.")
        return

    by_cat: dict = defaultdict(list)
    for m in all_mods[:60]:
        by_cat[m.category].append(m)

    lines = [f"🔧 <b>Modules{' — ' + category_filter.upper() if category_filter else ''}</b>\n"]
    for cat in sorted(by_cat):
        lines.append(f"\n<b>{cat.upper()}</b>")
        for m in by_cat[cat][:8]:
            lines.append(f"  <code>{m.id}</code> — {m.name}")

    if len(all_mods) > 60:
        remaining = len(all_mods) - 60
        lines.append(f"\n… {remaining} more. Filter: /modules injection")

    send_message(chat_id, "\n".join(lines))


def _cmd_scan(args, chat_id):
    session = _require_auth(chat_id)
    if not session:
        return

    if len(args) < 2:
        send_message(
            chat_id,
            "Usage: /scan <code>MODULE_ID TARGET_URL</code>\n"
            "Example: <code>/scan V-01 https://example.com</code>\n\n"
            "Use /modules to find a module ID.",
        )
        return

    module_id = args[0].upper()
    target_url = args[1]

    from apps.modules.engine import ModuleRegistry

    module = ModuleRegistry.instance().get(module_id)
    if not module:
        send_message(chat_id, f"/x\\ Module <code>{module_id}</code> not found. Use /modules to browse.")
        return

    target_field = _find_url_field(module)
    if not target_field:
        send_message(
            chat_id,
            f"/x\\ Module <code>{module_id}</code> requires complex parameters.\n"
            "Please configure it from the web UI.",
        )
        return

    from apps.scans.models import ScanJob
    from apps.targets.models import Project
    from django.db.models import Q
    from pentools.crypto import encrypt_sensitive_params

    user = session.user
    project = (
        Project.objects.filter(Q(owner=user) | Q(members=user))
        .order_by("-created_at")
        .first()
    )

    raw_params = {target_field: target_url}
    encrypted_params = encrypt_sensitive_params(raw_params, module)

    job = ScanJob.objects.create(
        module_id=module.id,
        params=encrypted_params,
        created_by=user,
        project=project,
        status=ScanJob.Status.PENDING,
    )

    from apps.scans.tasks import execute_module as exec_task

    task = exec_task.apply_async(args=[str(job.id)], queue=module.celery_queue)
    job.celery_task_id = task.id
    job.save(update_fields=["celery_task_id"])

    send_message(
        chat_id,
        f"/0\\ <b>Scan launched!</b>\n\n"
        f"Module: <code>{module.id}</code> — {module.name}\n"
        f"Target: <code>{target_url}</code>\n"
        f"Job:    <code>{str(job.id)[:8]}</code>\n\n"
        f"Follow up with:\n"
        f"/status {str(job.id)[:8]}\n"
        f"/findings {str(job.id)[:8]}",
    )


def _find_url_field(module) -> Optional[str]:
    """Return the primary URL/target parameter key for the module, or None."""
    schema = getattr(module, "PARAMETER_SCHEMA", None) or []
    # 1. Required url field
    for f in schema:
        if getattr(f, "field_type", "") == "url" and getattr(f, "required", False):
            return f.key
    # 2. Any url field
    for f in schema:
        if getattr(f, "field_type", "") == "url":
            return f.key
    # 3. Key contains 'target' or 'url'
    for f in schema:
        k = f.key.lower()
        if "target" in k or "url" in k:
            return f.key
    # 4. First required field
    for f in schema:
        if getattr(f, "required", False):
            return f.key
    return None


def _resolve_job(job_prefix: str, user):
    """Find a ScanJob by UUID prefix (first 8+ chars)."""
    from apps.scans.models import ScanJob

    prefix = job_prefix.lower().strip()
    if len(prefix) < 4:
        return None

    # Try DB-level filter (UUIDs stored as lowercase hex with dashes)
    recent = list(ScanJob.objects.filter(created_by=user).order_by("-created_at")[:200])
    matches = [j for j in recent if str(j.id).replace("-", "").startswith(prefix.replace("-", ""))]
    return matches[0] if matches else None


def _cmd_status(args, chat_id):
    session = _require_auth(chat_id)
    if not session:
        return
    if not args:
        send_message(chat_id, "Usage: /status <code>JOB_ID</code>")
        return

    job = _resolve_job(args[0], session.user)
    if not job:
        send_message(chat_id, f"/x\\ Scan not found: <code>{args[0]}</code>")
        return

    _STATUS_ICON = {
        "pending": "[Pen]", "running": "[Run]", "done": "[Done]",
        "failed": "[Fail]", "cancelled": "[Canc]", "paused": "[Pause]",
    }
    icon = _STATUS_ICON.get(job.status, "[?]")
    duration = f"{job.duration_seconds}s" if job.duration_seconds else "—"

    send_message(
        chat_id,
        f"{icon} <b>Scan Status</b>\n\n"
        f"Module:   <code>{job.module_id}</code>\n"
        f"Status:   <b>{job.status.upper()}</b>\n"
        f"Progress: {job.progress}%\n"
        f"Duration: {duration}\n"
        f"Findings: {job.finding_count} "
        f"(🔴{job.critical_count} 🟠{job.high_count} 🟡{job.medium_count} 🔵{job.low_count})\n"
        f"ID: <code>{str(job.id)}</code>",
    )


def _cmd_findings(args, chat_id):
    session = _require_auth(chat_id)
    if not session:
        return
    if not args:
        send_message(chat_id, "Usage: /findings <code>JOB_ID</code>")
        return

    job = _resolve_job(args[0], session.user)
    if not job:
        send_message(chat_id, f"/x\\ Scan not found: <code>{args[0]}</code>")
        return

    from apps.results.models import Finding

    findings = Finding.objects.filter(scan_job=job).order_by("severity")[:20]
    if not findings:
        send_message(chat_id, f"No findings recorded for <code>{str(job.id)[:8]}</code>.")
        return

    _SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
    lines = [f"🔍 <b>Findings: {job.module_id}</b> ({job.finding_count} total)\n"]
    for f in findings[:15]:
        icon = _SEV_ICON.get(f.severity, "⚪")
        title = f.title[:70] + ("…" if len(f.title) > 70 else "")
        lines.append(f"{icon} <b>{f.severity.upper()}</b> — {title}")

    if job.finding_count > 15:
        lines.append(f"\n… {job.finding_count - 15} more. View all in the web UI.")

    send_message(chat_id, "\n".join(lines))


def _cmd_cancel(args, chat_id):
    session = _require_auth(chat_id)
    if not session:
        return
    if not args:
        send_message(chat_id, "Usage: /cancel <code>JOB_ID</code>")
        return

    job = _resolve_job(args[0], session.user)
    if not job:
        send_message(chat_id, f"/x\\ Scan not found: <code>{args[0]}</code>")
        return

    if job.status not in ("pending", "running"):
        send_message(chat_id, f"Cannot cancel: scan is already <b>{job.status}</b>.")
        return

    from celery.result import AsyncResult
    from django.utils import timezone

    if job.celery_task_id:
        AsyncResult(job.celery_task_id).revoke(terminate=True, signal="SIGTERM")

    job.status = "cancelled"
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "finished_at"])

    send_message(chat_id, f"/0\\ Scan <code>{str(job.id)[:8]}</code> cancelled.")


def _cmd_recent(args, chat_id):
    session = _require_auth(chat_id)
    if not session:
        return

    from apps.scans.models import ScanJob

    jobs = ScanJob.objects.filter(created_by=session.user).order_by("-created_at")[:5]
    if not jobs:
        send_message(chat_id, "No recent scans. Try: /scan V-01 https://example.com")
        return

    _STATUS_ICON = {
        "pending": "[Pen]", "running": "[Run]", "done": "[Done]",
        "failed": "[Fail]", "cancelled": "[Canc]", "paused": "[Pause]",
    }
    lines = ["<b>Recent Scans:</b>\n"]
    for job in jobs:
        icon = _STATUS_ICON.get(job.status, "[?]")
        lines.append(
            f"{icon} <code>{job.module_id}</code> — {job.status.upper()} "
            f"({job.finding_count} findings)\n"
            f"  ID: <code>{str(job.id)[:8]}</code>"
        )
    send_message(chat_id, "\n".join(lines))


# ── Called from execute_module task on scan completion ────────────────────────

def notify_user_scan_complete(user, job) -> None:
    """
    Send a Telegram notification directly to the user's bot session when a scan
    finishes. Called from apps.scans.tasks.execute_module after job finalisation.
    """
    try:
        from .models import TelegramBotSession

        session = TelegramBotSession.objects.filter(user=user).first()
        if not session:
            return

        _STATUS_ICON = {"done": "[Done]", "failed": "[Fail]"}
        icon = _STATUS_ICON.get(job.status, "[?]")
        duration = f"{job.duration_seconds}s" if job.duration_seconds else "—"

        send_message(
            session.chat_id,
            f"{icon} <b>Scan Complete: {job.module_id}</b>\n\n"
            f"Status:   <b>{job.status.upper()}</b>\n"
            f"Duration: {duration}\n"
            f"Findings: {job.finding_count} "
            f"(🔴{job.critical_count} 🟠{job.high_count} 🟡{job.medium_count})\n\n"
            f"/status {str(job.id)[:8]}  |  /findings {str(job.id)[:8]}",
        )
    except Exception as exc:
        logger.error("notify_user_scan_complete failed: %s", exc)
