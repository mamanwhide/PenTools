"""
Notification channel management views.
"""
from __future__ import annotations
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render, redirect
from django.views.decorators.http import require_POST, require_http_methods
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Q

from .models import NotificationChannel, NotificationLog


def _owned_channel(user, pk):
    ch = get_object_or_404(NotificationChannel, pk=pk)
    if ch.owner == user or user.is_admin_role:  # HIGH-08: use custom role
        return ch
    from django.core.exceptions import PermissionDenied
    raise PermissionDenied


@login_required
def channel_list(request):
    from apps.targets.models import Project

    projects = Project.objects.filter(
        Q(owner=request.user) | Q(members=request.user)
    ).distinct()

    channels = NotificationChannel.objects.filter(owner=request.user).select_related("project")
    logs = NotificationLog.objects.filter(channel__owner=request.user).select_related("channel")[:50]

    return render(request, "notifications/list.html", {
        "channels": channels,
        "logs": logs,
        "projects": projects,
        "event_choices": NotificationChannel.TriggerEvent.choices,
    })


@login_required
@require_http_methods(["GET", "POST"])
def channel_create(request):
    from apps.targets.models import Project

    projects = Project.objects.filter(
        Q(owner=request.user) | Q(members=request.user)
    ).distinct()

    if request.method == "POST":
        data = request.POST
        project_id = data.get("project") or None
        project = None
        if project_id:
            project = get_object_or_404(Project, pk=project_id)

        events = request.POST.getlist("trigger_events")

        ch = NotificationChannel.objects.create(
            owner=request.user,
            name=data.get("name", "").strip(),
            channel_type=data.get("channel_type", "slack"),
            project=project,
            is_active="is_active" in data,
            trigger_events=events,
            # Telegram
            telegram_bot_token=data.get("telegram_bot_token", "").strip(),
            telegram_chat_id=data.get("telegram_chat_id", "").strip(),
            # Slack
            slack_webhook_url=data.get("slack_webhook_url", "").strip(),
            # Email
            smtp_host=data.get("smtp_host", "").strip(),
            smtp_port=int(data.get("smtp_port", "587") or 587),
            smtp_use_tls="smtp_use_tls" in data,
            smtp_username=data.get("smtp_username", "").strip(),
            smtp_password=data.get("smtp_password", "").strip(),
            email_from=data.get("email_from", "").strip(),
            email_to=data.get("email_to", "").strip(),
        )
        messages.success(request, f"Channel '{ch.name}' created.")
        return redirect("channel_list")

    return render(request, "notifications/create.html", {
        "projects": projects,
        "channel_type_choices": NotificationChannel.ChannelType.choices,
        "event_choices": NotificationChannel.TriggerEvent.choices,
    })


@login_required
@require_POST
def channel_test(request, pk):
    channel = _owned_channel(request.user, pk)

    class FakeFinding:
        severity = "critical"
        title = "Test notification from PenTools"
        url = "https://test.pentools.local"
        description = "This is a test notification."
        cwe_id = "CWE-0"
        cve_id = ""

    from .dispatcher import _dispatch_channel
    try:
        _dispatch_channel(channel, "finding_critical", FakeFinding())
        return JsonResponse({"ok": True, "message": "Test notification sent."})
    except Exception as exc:
        return JsonResponse({"ok": False, "message": str(exc)}, status=400)


@login_required
@require_POST
def channel_toggle(request, pk):
    channel = _owned_channel(request.user, pk)
    channel.is_active = not channel.is_active
    channel.save(update_fields=["is_active", "updated_at"])
    return JsonResponse({"active": channel.is_active})


@login_required
@require_POST
def channel_delete(request, pk):
    channel = _owned_channel(request.user, pk)
    channel.delete()
    messages.success(request, "Channel deleted.")
    return redirect("channel_list")
