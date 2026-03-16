import uuid
import secrets
from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    """Extended user model with API key and role support."""

    class Role(models.TextChoices):
        VIEWER = "viewer", "Viewer"
        OPERATOR = "operator", "Operator"
        ADMIN = "admin", "Admin"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.OPERATOR)
    api_key = models.CharField(max_length=64, unique=True, blank=True)
    bio = models.TextField(blank=True)

    class Meta:
        db_table = "accounts_user"

    def save(self, *args, **kwargs):
        if not self.api_key:
            self.api_key = secrets.token_hex(32)
        super().save(*args, **kwargs)

    def regenerate_api_key(self):
        self.api_key = secrets.token_hex(32)
        self.save(update_fields=["api_key"])
        return self.api_key

    @property
    def is_admin_role(self):
        return self.role == self.Role.ADMIN

    @property
    def is_operator(self):
        return self.role in (self.Role.OPERATOR, self.Role.ADMIN)

    def __str__(self):
        return self.username
