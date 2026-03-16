from django.contrib import admin
from .models import NotificationChannel, NotificationLog


@admin.register(NotificationChannel)
class NotificationChannelAdmin(admin.ModelAdmin):
    list_display = ["name", "channel_type", "project", "owner", "is_active", "created_at"]
    list_filter  = ["channel_type", "is_active"]
    search_fields = ["name", "owner__username"]
    readonly_fields = ["created_at", "updated_at"]


@admin.register(NotificationLog)
class NotificationLogAdmin(admin.ModelAdmin):
    list_display = ["channel", "event", "result", "sent_at"]
    list_filter  = ["result", "event"]
    readonly_fields = ["sent_at"]
