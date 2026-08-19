"""Standard NetBox changelog for PassworkBinding.

core.ObjectChange records are created by NetBox signals only inside
an HTTP request (middleware puts the request into a contextvar), so these
tests go through the full stack — django.test.Client, not RequestFactory.
"""

import json

import pytest
from core.models import ObjectChange
from django.contrib.contenttypes.models import ContentType

from netbox_passwork.models import PassworkBinding
from netbox_passwork.tests.conftest import grant_netbox_perm

API = "/plugins/passwork"


def _binding_changes(binding_id):
    ct = ContentType.objects.get_for_model(PassworkBinding)
    return ObjectChange.objects.filter(
        changed_object_type=ct,
        changed_object_id=binding_id,
    )


@pytest.mark.django_db
class TestBindingChangelog:
    def test_create_writes_objectchange(self, client, user):
        grant_netbox_perm(user, "add_binding")
        client.force_login(user)

        resp = client.post(
            f"{API}/bindings/",
            data=json.dumps(
                {
                    "object_type": "device",
                    "object_id": 7,
                    "passwork_item_id": "pw_cl_001",
                }
            ),
            content_type="application/json",
        )
        assert resp.status_code == 201
        binding_id = resp.json()["id"]

        change = _binding_changes(binding_id).get(action="create")
        assert change.user == user
        assert change.postchange_data["passwork_item_id"] == "pw_cl_001"
        # created_by in Post-Change Data is human-readable: '<username> (<id>)'
        assert change.postchange_data["created_by"] == f"{user} ({user.pk})"
        assert change.prechange_data is None

    def test_delete_writes_objectchange(self, client, user, binding):
        grant_netbox_perm(user, "delete_binding")
        client.force_login(user)

        resp = client.delete(f"{API}/bindings/{binding.pk}/")
        assert resp.status_code == 200
        assert not PassworkBinding.objects.filter(pk=binding.pk).exists()

        change = _binding_changes(binding.pk).get(action="delete")
        assert change.user == user
        # The pre-deletion state snapshot is stored in prechange_data
        assert change.prechange_data["passwork_item_id"] == "abc123"
        # created_by in Pre-Change Data is human-readable: '<username> (<id>)'
        assert change.prechange_data["created_by"] == f"{binding.created_by} ({binding.created_by_id})"

    def test_factory_save_without_request_writes_nothing(self, binding):
        # Saving outside an HTTP request (fixtures, shell) writes no changelog
        assert not _binding_changes(binding.pk).exists()
