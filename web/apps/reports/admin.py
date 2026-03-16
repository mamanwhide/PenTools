from django.contrib import admin
from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ["title", "project", "status", "last_format", "generated_at", "created_by", "created_at"]
    list_filter = ["status", "last_format"]
    search_fields = ["title", "project__name"]
    readonly_fields = ["created_at", "updated_at", "generated_at", "celery_task_id"]
