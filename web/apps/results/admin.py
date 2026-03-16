from django.contrib import admin
from .models import Finding, FindingStatusHistory


class FindingStatusHistoryInline(admin.TabularInline):
    model = FindingStatusHistory
    extra = 0
    readonly_fields = ["from_status", "to_status", "changed_by", "note", "changed_at"]
    can_delete = False


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = [
        "title", "severity", "status", "project", "scan_job",
        "is_manual", "cvss_score", "cve_id", "created_at",
    ]
    list_filter = ["severity", "status", "is_manual"]
    search_fields = ["title", "url", "cve_id", "cwe_id", "description"]
    readonly_fields = ["evidence_hash", "created_at", "updated_at"]
    inlines = [FindingStatusHistoryInline]
    fieldsets = [
        ("Core", {"fields": ("title", "severity", "status", "url", "project", "scan_job", "is_manual")}),
        ("Details", {"fields": ("description", "evidence", "evidence_hash", "remediation")}),
        ("Scoring", {"fields": ("cvss_score", "cvss_vector", "cve_id", "cwe_id")}),
        ("Meta", {"fields": ("notes", "assigned_to", "created_by", "raw_data")}),
        ("Timestamps", {"fields": ("created_at", "updated_at")}),
    ]


@admin.register(FindingStatusHistory)
class FindingStatusHistoryAdmin(admin.ModelAdmin):
    list_display = ["finding", "from_status", "to_status", "changed_by", "changed_at"]
    list_filter = ["to_status"]
    readonly_fields = ["changed_at"]
