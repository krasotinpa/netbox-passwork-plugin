from django.conf import settings
from django.db import models
from netbox.models import ChangeLoggedModel


def object_model(object_type: str):
    """Model class behind a binding's ``object_type``; None — unknown type."""
    from dcim.models import Device
    from ipam.models import Service
    from virtualization.models import VirtualMachine

    return {
        "device": Device,
        "vm": VirtualMachine,
        "service": Service,
    }.get(object_type)


class PassworkBinding(ChangeLoggedModel):
    """Binding of a NetBox object to a Passwork item.

    Change history (creation/deletion) is tracked by the standard NetBox
    changelog (core.ObjectChange) via inheritance from ChangeLoggedModel.
    """

    OBJECT_TYPE_CHOICES = [
        ("device", "Device"),
        ("vm", "Virtual Machine"),
        ("service", "Service"),
    ]

    object_type = models.CharField(max_length=32, choices=OBJECT_TYPE_CHOICES)
    object_id = models.PositiveIntegerField()
    passwork_item_id = models.CharField(max_length=128, db_index=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )

    class Meta:
        indexes = [
            models.Index(
                fields=["object_type", "object_id"],
                name="pb_object_idx",
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["object_type", "object_id", "passwork_item_id"],
                name="pb_unique_binding",
            ),
        ]
        permissions = [
            ("view_secrets", "Can view Passwork secrets"),
            ("reveal_secret", "Can reveal Passwork secret value"),
            ("add_binding", "Can create Passwork binding"),
            ("delete_binding", "Can delete Passwork binding"),
            ("view_auditlog", "Can view Passwork audit log"),
        ]

    def _resolved_object(self):
        """Returns the live NetBox object for (object_type, object_id), or None."""
        model = object_model(self.object_type)
        if not model:
            return None
        return model.objects.filter(pk=self.object_id).first()

    def get_absolute_url(self):
        """URL of the related object — so the object column in the changelog links to it."""
        obj = self._resolved_object()
        return obj.get_absolute_url() if obj else None

    def serialize_object(self, exclude=None):
        """created_by in the changelog snapshot — as '<username> (<id>)' instead of a raw id."""
        data = super().serialize_object(exclude=exclude)
        if "created_by" in data and self.created_by_id:
            data["created_by"] = f"{self.created_by} ({self.created_by_id})"
        return data

    def __str__(self):
        obj = self._resolved_object()
        if obj is not None:
            return f"{obj} → {self.passwork_item_id}"
        return f"{self.object_type}:{self.object_id} → {self.passwork_item_id}"


class PassworkAuditLog(models.Model):
    ACTION_CHOICES = [
        ("reveal", "Reveal"),
        ("copy", "Copy"),
    ]

    timestamp = models.DateTimeField(auto_now_add=True)
    netbox_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        on_delete=models.SET_NULL,
    )
    passwork_item_id = models.CharField(max_length=128)
    object_type = models.CharField(max_length=32)
    object_id = models.PositiveIntegerField()
    action = models.CharField(max_length=16, choices=ACTION_CHOICES)
    ip_address = models.GenericIPAddressField(null=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["netbox_user"], name="pal_user_idx"),
            models.Index(fields=["passwork_item_id"], name="pal_item_idx"),
            models.Index(fields=["-timestamp"], name="pal_ts_idx"),
        ]

    def __str__(self):
        return f"{self.action} {self.passwork_item_id} by {self.netbox_user_id}"
