"""Move binding history over to the standard NetBox changelog.

- The PassworkBindingHistory table is dropped (accumulated records are
  deliberately not migrated).
- Soft delete (deleted_at/deleted_by) is replaced with hard delete: soft-deleted
  records are physically removed, the partial index/constraint become regular ones.
- PassworkBinding gains the created/last_updated fields from ChangeLoggedModel
  (created is populated from the former created_at via RenameField).

WARNING: this migration is irreversible without a database backup — the history
table and soft-deleted bindings are removed permanently.
"""

from django.conf import settings
from django.db import migrations, models


def purge_soft_deleted_bindings(apps, schema_editor):
    # Raw SQL, not ORM .delete(): by this point DeleteModel has already dropped
    # the PassworkBindingHistory table, but the PassworkBinding model still has
    # a PROTECT back-reference to it. An ORM cascade (collector) on .delete()
    # would hit the now-missing history table and fail with
    # UndefinedTable. A direct DELETE bypasses the collector; history rows are
    # already gone along with the table. The deleted_at column still exists
    # at this point (RemoveField comes later).
    schema_editor.execute('DELETE FROM "netbox_passwork_passworkbinding" WHERE "deleted_at" IS NOT NULL')


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("netbox_passwork", "0002_alter_ids"),
    ]

    operations = [
        # History table first (FK PROTECT on PassworkBinding), then the
        # physical removal of soft-deleted bindings — before applying the
        # unconditional unique constraint.
        migrations.DeleteModel(name="PassworkBindingHistory"),
        migrations.RunPython(purge_soft_deleted_bindings, migrations.RunPython.noop),
        # The partial index/constraint reference deleted_at — drop them
        # before removing the field itself.
        migrations.RemoveConstraint(
            model_name="passworkbinding",
            name="pb_unique_active_binding",
        ),
        migrations.RemoveIndex(
            model_name="passworkbinding",
            name="pb_active_object_idx",
        ),
        migrations.RemoveField(model_name="passworkbinding", name="deleted_at"),
        migrations.RemoveField(model_name="passworkbinding", name="deleted_by"),
        # created_at -> created (ChangeLoggedModel field), values are preserved.
        migrations.RenameField(
            model_name="passworkbinding",
            old_name="created_at",
            new_name="created",
        ),
        migrations.AlterField(
            model_name="passworkbinding",
            name="created",
            field=models.DateTimeField(auto_now_add=True, blank=True, null=True, verbose_name="created"),
        ),
        migrations.AddField(
            model_name="passworkbinding",
            name="last_updated",
            field=models.DateTimeField(auto_now=True, blank=True, null=True, verbose_name="last updated"),
        ),
        migrations.AddIndex(
            model_name="passworkbinding",
            index=models.Index(fields=["object_type", "object_id"], name="pb_object_idx"),
        ),
        migrations.AddConstraint(
            model_name="passworkbinding",
            constraint=models.UniqueConstraint(
                fields=["object_type", "object_id", "passwork_item_id"],
                name="pb_unique_binding",
            ),
        ),
    ]
