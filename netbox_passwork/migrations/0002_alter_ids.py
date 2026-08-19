from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_passwork", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="passworkauditlog",
            name="id",
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name="passworkbinding",
            name="id",
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False),
        ),
        migrations.AlterField(
            model_name="passworkbindinghistory",
            name="id",
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False),
        ),
    ]
