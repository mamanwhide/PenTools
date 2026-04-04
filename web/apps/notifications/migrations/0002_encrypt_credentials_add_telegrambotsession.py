"""
Migration 0002: Encrypt sensitive credential fields + add TelegramBotSession.
"""
from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import pentools.encrypted_fields


class Migration(migrations.Migration):

    dependencies = [
        ("notifications", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AlterField(
            model_name="notificationchannel",
            name="telegram_bot_token",
            field=pentools.encrypted_fields.EncryptedCharField(blank=True, default=""),
        ),
        migrations.AlterField(
            model_name="notificationchannel",
            name="slack_webhook_url",
            field=pentools.encrypted_fields.EncryptedCharField(blank=True, default=""),
        ),
        migrations.AlterField(
            model_name="notificationchannel",
            name="smtp_password",
            field=pentools.encrypted_fields.EncryptedCharField(blank=True, default=""),
        ),
        migrations.CreateModel(
            name="TelegramBotSession",
            fields=[
                ("id", models.AutoField(
                    auto_created=True, primary_key=True, serialize=False, verbose_name="ID"
                )),
                ("chat_id", models.CharField(db_index=True, max_length=100, unique=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("last_seen", models.DateTimeField(auto_now=True)),
                ("user", models.OneToOneField(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="telegram_bot_session",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={
                "db_table": "notifications_telegrambotsession",
            },
        ),
    ]
