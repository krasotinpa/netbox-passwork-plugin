"""Passwork tab badge (`_passwork_badge`).

Regression: the badge is invoked on every NetBox object page render
(Device/VM/Service) and used to filter by the removed `deleted_at` field,
which made the page fail with a FieldError. These tests call the function
directly with a lightweight stub that mirrors the interface it actually reads
(`instance._meta.model_name`, `instance.pk`).
"""

import pytest

from netbox_passwork.models import PassworkBinding
from netbox_passwork.template_extensions import _passwork_badge


class _Meta:
    def __init__(self, model_name):
        self.model_name = model_name


class _Stub:
    def __init__(self, model_name, pk):
        self._meta = _Meta(model_name)
        self.pk = pk


@pytest.mark.django_db
class TestPassworkBadge:
    def test_counts_bindings_for_device(self, user):
        PassworkBinding.objects.create(object_type="device", object_id=7, passwork_item_id="pw_a", created_by=user)
        PassworkBinding.objects.create(object_type="device", object_id=7, passwork_item_id="pw_b", created_by=user)
        assert _passwork_badge(_Stub("device", 7)) == 2

    def test_zero_when_no_bindings(self):
        assert _passwork_badge(_Stub("device", 12345)) == 0

    def test_maps_virtualmachine_to_vm(self, user):
        PassworkBinding.objects.create(object_type="vm", object_id=3, passwork_item_id="pw_vm", created_by=user)
        assert _passwork_badge(_Stub("virtualmachine", 3)) == 1

    def test_unknown_model_returns_zero(self):
        assert _passwork_badge(_Stub("interface", 1)) == 0
