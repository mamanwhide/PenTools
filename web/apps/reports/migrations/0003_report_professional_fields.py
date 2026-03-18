from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("reports", "0002_add_targets_to_report"),
    ]

    operations = [
        migrations.AddField(
            model_name="report",
            name="engagement_type",
            field=models.CharField(
                choices=[
                    ("black-box", "Black-Box"),
                    ("grey-box",  "Grey-Box"),
                    ("white-box", "White-Box"),
                    ("hybrid",    "Hybrid"),
                ],
                default="black-box",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="report",
            name="methodology_notes",
            field=models.TextField(
                blank=True,
                help_text="Testing approach & methodology description (appended to Section 2)",
            ),
        ),
        migrations.AddField(
            model_name="report",
            name="scope_notes",
            field=models.TextField(
                blank=True,
                help_text="Additional Scope of Work context (appended to Section 3)",
            ),
        ),
    ]
