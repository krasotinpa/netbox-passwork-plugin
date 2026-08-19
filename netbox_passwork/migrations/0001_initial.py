import django.db.models.deletion
import django.db.models.expressions
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="PassworkBinding",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False)),
                (
                    "object_type",
                    models.CharField(
                        choices=[("device", "Device"), ("vm", "Virtual Machine"), ("service", "Service")],
                        max_length=32,
                    ),
                ),
                ("object_id", models.PositiveIntegerField()),
                ("passwork_item_id", models.CharField(db_index=True, max_length=128)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("deleted_at", models.DateTimeField(blank=True, null=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "deleted_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "permissions": [
                    ("view_secrets", "Can view Passwork secrets"),
                    ("reveal_secret", "Can reveal Passwork secret value"),
                    ("add_binding", "Can create Passwork binding"),
                    ("delete_binding", "Can delete Passwork binding"),
                    ("view_auditlog", "Can view Passwork audit log"),
                ],
            },
        ),
        migrations.CreateModel(
            name="PassworkBindingHistory",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                (
                    "action",
                    models.CharField(
                        choices=[("created", "Created"), ("deleted", "Deleted"), ("restored", "Restored")],
                        max_length=16,
                    ),
                ),
                ("ip_address", models.GenericIPAddressField(null=True)),
                (
                    "binding",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="history",
                        to="netbox_passwork.passworkbinding",
                    ),
                ),
                (
                    "netbox_user",
                    models.ForeignKey(
                        null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL
                    ),
                ),
            ],
            options={
                "ordering": ["-timestamp"],
            },
        ),
        migrations.CreateModel(
            name="PassworkAuditLog",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False)),
                ("timestamp", models.DateTimeField(auto_now_add=True)),
                ("passwork_item_id", models.CharField(max_length=128)),
                ("object_type", models.CharField(max_length=32)),
                ("object_id", models.PositiveIntegerField()),
                ("action", models.CharField(choices=[("reveal", "Reveal"), ("copy", "Copy")], max_length=16)),
                ("ip_address", models.GenericIPAddressField(null=True)),
                (
                    "netbox_user",
                    models.ForeignKey(
                        null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL
                    ),
                ),
            ],
            options={
                "ordering": ["-timestamp"],
            },
        ),
        migrations.AddIndex(
            model_name="passworkbinding",
            index=models.Index(
                condition=models.Q(deleted_at__isnull=True),
                fields=["object_type", "object_id"],
                name="pb_active_object_idx",
            ),
        ),
        migrations.AddConstraint(
            model_name="passworkbinding",
            constraint=models.UniqueConstraint(
                condition=models.Q(deleted_at__isnull=True),
                fields=["object_type", "object_id", "passwork_item_id"],
                name="pb_unique_active_binding",
            ),
        ),
        migrations.AddIndex(
            model_name="passworkauditlog",
            index=models.Index(fields=["netbox_user"], name="pal_user_idx"),
        ),
        migrations.AddIndex(
            model_name="passworkauditlog",
            index=models.Index(fields=["passwork_item_id"], name="pal_item_idx"),
        ),
        migrations.AddIndex(
            model_name="passworkauditlog",
            index=models.Index(fields=["-timestamp"], name="pal_ts_idx"),
        ),
    ]
