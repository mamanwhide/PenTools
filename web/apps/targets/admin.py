from django.contrib import admin
from .models import Project, Target, AuthContext


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ["name", "owner", "is_active", "created_at"]
    list_filter = ["is_active"]
    search_fields = ["name", "owner__username"]


@admin.register(Target)
class TargetAdmin(admin.ModelAdmin):
    list_display = ["name", "target_type", "value", "project", "is_in_scope", "created_at"]
    list_filter = ["target_type", "is_in_scope"]
    search_fields = ["name", "value"]


@admin.register(AuthContext)
class AuthContextAdmin(admin.ModelAdmin):
    list_display = ["name", "auth_type", "project", "is_active", "created_by", "created_at"]
    list_filter = ["auth_type", "is_active"]
    search_fields = ["name", "project__name"]
    readonly_fields = ["created_at", "updated_at"]
