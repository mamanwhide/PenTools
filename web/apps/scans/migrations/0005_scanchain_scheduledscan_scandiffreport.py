from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


class Migration(migrations.Migration):

    dependencies = [
        ("scans", "0004_alter_scanjobtemplate_table"),
        ("targets", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ── ScanChain ─────────────────────────────────────────────────────────
        migrations.CreateModel(
            name="ScanChain",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("parent_module", models.CharField(db_index=True, max_length=100)),
                ("child_module", models.CharField(max_length=100)),
                ("trigger_on", models.CharField(
                    choices=[("done", "On Success"), ("always", "Always (success or failure)")],
                    default="done", max_length=10,
                )),
                ("param_mapping", models.JSONField(default=dict)),
                ("base_params", models.JSONField(default=dict)),
                ("is_active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("created_by", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="scan_chains",
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={"ordering": ["parent_module", "child_module"], "db_table": "scans_scanchain"},
        ),

        # ── ScheduledScan ─────────────────────────────────────────────────────
        migrations.CreateModel(
            name="ScheduledScan",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("name", models.CharField(max_length=200)),
                ("module_id", models.CharField(db_index=True, max_length=100)),
                ("params", models.JSONField(default=dict)),
                ("schedule", models.CharField(
                    choices=[
                        ("hourly",   "Every hour"),
                        ("daily",    "Daily"),
                        ("weekly",   "Weekly"),
                        ("biweekly", "Every 2 weeks"),
                        ("monthly",  "Monthly"),
                    ],
                    default="daily", max_length=20,
                )),
                ("is_active", models.BooleanField(default=True)),
                ("periodic_task_name", models.CharField(blank=True, db_index=True, max_length=200)),
                ("last_run_at", models.DateTimeField(blank=True, null=True)),
                ("next_run_at", models.DateTimeField(blank=True, null=True)),
                ("run_count", models.PositiveIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("created_by", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="scheduled_scans",
                    to=settings.AUTH_USER_MODEL,
                )),
                ("project", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="scheduled_scans",
                    to="targets.project",
                )),
                ("target", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="scheduled_scans",
                    to="targets.target",
                )),
            ],
            options={"ordering": ["-created_at"], "db_table": "scans_scheduledscan"},
        ),

        # ── ScanDiffReport ────────────────────────────────────────────────────
        migrations.CreateModel(
            name="ScanDiffReport",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("module_id", models.CharField(db_index=True, max_length=100)),
                ("new_count", models.PositiveIntegerField(default=0)),
                ("resolved_count", models.PositiveIntegerField(default=0)),
                ("unchanged_count", models.PositiveIntegerField(default=0)),
                ("new_critical", models.PositiveIntegerField(default=0)),
                ("new_high", models.PositiveIntegerField(default=0)),
                ("diff_data", models.JSONField(default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("baseline_job", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="diff_as_baseline",
                    to="scans.scanjob",
                )),
                ("current_job", models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name="diff_as_current",
                    to="scans.scanjob",
                )),
                ("project", models.ForeignKey(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name="diff_reports",
                    to="targets.project",
                )),
            ],
            options={
                "ordering": ["-created_at"],
                "db_table": "scans_scandiffreport",
                "indexes": [models.Index(fields=["module_id", "project"], name="scans_diff_module_project_idx")],
            },
        ),
    ]
