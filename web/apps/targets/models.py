from django.db import models
from django.conf import settings
import uuid


class Project(models.Model):
    """An engagement / pentest scope that groups targets and scans."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="projects",
    )
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="member_projects",
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.name


class Target(models.Model):
    class TargetType(models.TextChoices):
        URL = "url", "URL"
        DOMAIN = "domain", "Domain"
        IP = "ip", "IP Address"
        CIDR = "cidr", "CIDR Range"
        WILDCARD = "wildcard", "Wildcard Domain"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="targets")
    name = models.CharField(max_length=200)
    target_type = models.CharField(max_length=20, choices=TargetType.choices)
    value = models.CharField(max_length=500)
    description = models.TextField(blank=True)
    tags = models.JSONField(default=list, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="targets",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    is_in_scope = models.BooleanField(default=True)

    class Meta:
        ordering = ["-created_at"]
        unique_together = [("project", "value")]

    def __str__(self):
        return f"{self.name} ({self.value})"


class AuthContext(models.Model):
    """A saved authentication context (session) for multi-role testing within a project."""

    class AuthType(models.TextChoices):
        NONE = "none", "Unauthenticated"
        BEARER = "bearer", "Bearer JWT"
        BASIC = "basic", "Basic Auth (Base64)"
        COOKIE = "cookie", "Cookie"
        API_KEY = "api_key", "API Key"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    project = models.ForeignKey(
        Project, on_delete=models.CASCADE, related_name="auth_contexts"
    )
    name = models.CharField(max_length=100, help_text="Human label, e.g. 'Admin Role'")
    auth_type = models.CharField(
        max_length=20, choices=AuthType.choices, default=AuthType.NONE
    )
    # Credential value — stored at rest; masked in API list responses
    auth_value = models.TextField(blank=True, help_text="Token / cookie value / base64 basic creds")
    # Optional header name for api_key type (e.g. 'X-API-Key')
    header_name = models.CharField(max_length=100, blank=True, default="Authorization")
    # Marks which context is active for quick-switch in the UI
    is_active = models.BooleanField(default=False)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="auth_contexts",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        unique_together = [("project", "name")]

    def __str__(self):
        return f"{self.name} ({self.auth_type}) — {self.project}"

    def save(self, *args, **kwargs):
        """Ensure only one context per project is marked active at a time."""
        if self.is_active:
            AuthContext.objects.filter(project=self.project, is_active=True).exclude(
                pk=self.pk
            ).update(is_active=False)
        super().save(*args, **kwargs)
