from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('scans', '0003_fix_scanjobtemplate_fields'),
    ]

    operations = [
        migrations.AlterModelTable(
            name='scanjobtemplate',
            table='scans_scanjobtemplate',
        ),
    ]
