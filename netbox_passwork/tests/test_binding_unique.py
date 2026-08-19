import pytest
from django.db import IntegrityError

from netbox_passwork.models import PassworkBinding


@pytest.mark.django_db
class TestPassworkBindingUnique:
    def _make(self, user, object_id=1, pw_id="pw_dup"):
        b = PassworkBinding(
            object_type="device",
            object_id=object_id,
            passwork_item_id=pw_id,
            created_by=user,
        )
        b.save()
        return b

    def test_duplicate_binding_raises(self, user):
        self._make(user)
        with pytest.raises(IntegrityError):
            self._make(user)

    def test_duplicate_allowed_after_delete(self, user, other_user):
        b = self._make(user)
        b.delete()

        # After deletion — a new binding is allowed
        b2 = self._make(other_user)
        assert b2.pk is not None

    def test_same_pw_different_object_allowed(self, user):
        self._make(user, object_id=1)
        b2 = self._make(user, object_id=2)
        assert b2.pk is not None
