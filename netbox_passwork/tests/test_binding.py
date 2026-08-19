import pytest

from netbox_passwork.models import PassworkBinding


@pytest.mark.django_db
class TestPassworkBindingCreate:
    def test_create_binding(self, user):
        b = PassworkBinding(
            object_type="device",
            object_id=42,
            passwork_item_id="pw_001",
            created_by=user,
        )
        b.save()

        assert b.pk is not None
        assert b.created is not None
        assert b.created_by == user

    def test_hard_delete(self, binding):
        pk = binding.pk
        binding.delete()

        assert not PassworkBinding.objects.filter(pk=pk).exists()


@pytest.mark.django_db
class TestPassworkBindingStr:
    def test_str_binding_fallback(self, binding):
        # No real object with this id exists in the test DB → technical fallback
        assert str(binding) == "device:1 → abc123"

    def test_str_binding_resolved_name(self, user):
        # When a real object exists, str() shows its name, not device:<id>
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

        site = Site.objects.create(name="S1", slug="s1")
        mfr = Manufacturer.objects.create(name="M1", slug="m1")
        dtype = DeviceType.objects.create(manufacturer=mfr, model="T1", slug="t1")
        role = DeviceRole.objects.create(name="R1", slug="r1")
        device = Device.objects.create(name="SW-01", site=site, device_type=dtype, role=role)

        b = PassworkBinding.objects.create(
            object_type="device",
            object_id=device.pk,
            passwork_item_id="pw_resolved",
            created_by=user,
        )
        assert str(b) == "SW-01 → pw_resolved"
        assert "device:" not in str(b)

    def test_get_absolute_url_resolved(self, user):
        from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

        site = Site.objects.create(name="S2", slug="s2")
        mfr = Manufacturer.objects.create(name="M2", slug="m2")
        dtype = DeviceType.objects.create(manufacturer=mfr, model="T2", slug="t2")
        role = DeviceRole.objects.create(name="R2", slug="r2")
        device = Device.objects.create(name="SW-02", site=site, device_type=dtype, role=role)

        b = PassworkBinding.objects.create(
            object_type="device",
            object_id=device.pk,
            passwork_item_id="pw_url",
            created_by=user,
        )
        assert b.get_absolute_url() == device.get_absolute_url()

    def test_get_absolute_url_missing_object(self, binding):
        # No real object → no link (the column renders plain text)
        assert binding.get_absolute_url() is None

    def test_serialize_object_created_by_format(self, binding, user):
        data = binding.serialize_object()
        assert data["created_by"] == f"{user} ({user.pk})"

    def test_str_auditlog(self, user):
        from netbox_passwork.models import PassworkAuditLog

        log = PassworkAuditLog.objects.create(
            netbox_user=user,
            passwork_item_id="pw_str",
            object_type="device",
            object_id=1,
            action="reveal",
            ip_address="127.0.0.1",
        )
        assert "reveal" in str(log)
