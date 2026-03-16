from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0002_scanjobtemplate'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scanjobtemplate',
            name='module_id',
            field=models.CharField(db_index=True, max_length=100),
        ),
        migrations.AlterField(
            model_name='scanjobtemplate',
            name='name',
            field=models.CharField(max_length=200),
        ),
    ]
