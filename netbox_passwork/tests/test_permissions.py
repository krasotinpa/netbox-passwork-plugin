import json

import pytest
from django.contrib.auth.models import AnonymousUser
from django.contrib.contenttypes.models import ContentType
from django.http import JsonResponse
from django.test import RequestFactory
from django.views import View

from netbox_passwork.models import PassworkBinding
from netbox_passwork.permissions import (
    RequireNetboxPermMixin,
    bound_object_access,
    require_netbox_perm,
)
from netbox_passwork.tests.conftest import (
    FakeGateway,
    grant_view_device,
    make_device,
)
from netbox_passwork.views import (
    BindingsCreateView,
    BindingsDeleteView,
    SecretCopyView,
    SecretDetailView,
    SecretsListView,
)


def _plain_view(request):
    return JsonResponse({"ok": True})


class _MixinView(RequireNetboxPermMixin, View):
    permission_required = "view_secrets"

    def get(self, request, *args, **kwargs):
        return JsonResponse({"ok": True})


def grant_netbox_perm(user, action):
    """
    Creates a NetBox ObjectPermission.
    action — one of the plugin's custom actions:
    view_secrets, reveal_secret, add_binding, delete_binding, view_auditlog
    """
    from users.models import ObjectPermission

    ct = ContentType.objects.get_for_model(PassworkBinding)
    op = ObjectPermission.objects.create(
        name=f"test_{action}_{user.pk}",
        actions=[action],
        constraints=None,
    )
    op.users.add(user)
    op.object_types.add(ct)
    if hasattr(user, "_object_perm_cache"):
        del user._object_perm_cache
    return op


@pytest.mark.django_db
class TestRequireNetboxPermDecorator:
    def setup_method(self):
        self.factory = RequestFactory()
        self.view = require_netbox_perm("view_secrets")(_plain_view)

    def test_unauthenticated_returns_401(self):
        request = self.factory.get("/")
        request.user = AnonymousUser()
        assert self.view(request).status_code == 401

    def test_no_permission_returns_403(self, user):
        request = self.factory.get("/")
        request.user = user
        assert self.view(request).status_code == 403

    def test_with_permission_returns_200(self, user):
        grant_netbox_perm(user, "view_secrets")
        request = self.factory.get("/")
        request.user = user
        assert self.view(request).status_code == 200


@pytest.mark.django_db
class TestRequireNetboxPermMixin:
    def setup_method(self):
        self.factory = RequestFactory()
        self.view = _MixinView.as_view()

    def test_unauthenticated_returns_401(self):
        request = self.factory.get("/")
        request.user = AnonymousUser()
        resp = self.view(request)
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"code": "not_authenticated", "detail": "Authentication required"}

    def test_no_permission_returns_403(self, user):
        request = self.factory.get("/")
        request.user = user
        resp = self.view(request)
        assert resp.status_code == 403
        assert json.loads(resp.content) == {"code": "netbox_permission_denied", "detail": "Permission denied"}

    def test_with_permission_returns_200(self, user):
        grant_netbox_perm(user, "view_secrets")
        request = self.factory.get("/")
        request.user = user
        assert self.view(request).status_code == 200


# ---------------------------------------------------------------------------
# Object-level permissions — issue #1 / ADR-0002
# ---------------------------------------------------------------------------

ITEM = {"name": "T", "login": "u", "password": "s", "description": "", "url": "", "custom_fields": []}

# The six object-scoped operations covered by the object gate
OPS = ["list", "detail", "reveal", "copy", "create", "delete"]

SITE_A_ONLY = {"site__slug": "site-a"}


def _grant_plugin_perms(user):
    for action in ("view_secrets", "reveal_secret", "add_binding", "delete_binding"):
        grant_netbox_perm(user, action)


@pytest.fixture
def device_b(db):
    """Device pk=2 in Site B — outside the SITE_A_ONLY constraint."""
    from dcim.models import Site

    site, _ = Site.objects.get_or_create(name="Site B", slug="site-b")
    return make_device(2, "dev-2", site)


@pytest.fixture
def binding_a(db, user, device):
    return PassworkBinding.objects.create(
        object_type="device", object_id=device.pk, passwork_item_id="pw_x", created_by=user
    )


@pytest.fixture
def binding_b(db, user, device_b):
    return PassworkBinding.objects.create(
        object_type="device", object_id=device_b.pk, passwork_item_id="pw_x", created_by=user
    )


@pytest.mark.django_db
class TestObjectGateMatrix:
    """
    The full matrix: six object-scoped operations × three outcomes — no plugin permission → 403,
    plugin permissions but the object outside the user's ``ObjectPermission`` constraints → 404,
    everything granted and the object inside the constraints → success.
    """

    def setup_method(self):
        self.factory = RequestFactory()
        self.fake = None

    def _call(self, op, user, target_device, pw_id="pw_x"):
        f = self.factory
        if op == "list":
            request = f.get("/secrets/", {"object_type": "device", "object_id": str(target_device.pk)})
            request.user = user
            request.session = {}
            return SecretsListView.as_view()(request)
        if op in ("detail", "reveal"):
            params = {"object_type": "device", "object_id": str(target_device.pk)}
            if op == "reveal":
                params["reveal"] = "true"
            self.fake = FakeGateway(get_item=ITEM)
            request = f.get(f"/secrets/{pw_id}/detail/", params)
            request.user = user
            request.session = {}
            return SecretDetailView.as_view(gateway_factory=lambda r: self.fake)(request, pw_id=pw_id)
        if op == "copy":
            self.fake = FakeGateway()
            request = f.post(f"/secrets/{pw_id}/copy/?object_type=device&object_id={target_device.pk}")
            request.user = user
            request.session = {}
            return SecretCopyView.as_view(gateway_factory=lambda r: self.fake)(request, pw_id=pw_id)
        if op == "create":
            body = {"object_type": "device", "object_id": target_device.pk, "passwork_item_id": "pw_created"}
            request = f.post("/bindings/", data=json.dumps(body), content_type="application/json")
            request.user = user
            request.session = {}
            return BindingsCreateView.as_view()(request)
        if op == "delete":
            b = PassworkBinding.objects.get(object_type="device", object_id=target_device.pk, passwork_item_id=pw_id)
            request = f.delete(f"/bindings/{b.pk}/")
            request.user = user
            request.session = {}
            return BindingsDeleteView.as_view()(request, binding_id=b.pk)
        raise AssertionError(f"unknown op {op}")

    @pytest.mark.parametrize("op", OPS)
    def test_without_plugin_permission_returns_403(self, op, user, device, binding_a):
        """The object is fully visible, but the plugin permission is missing → 403 (unchanged behaviour)."""
        grant_view_device(user)
        resp = self._call(op, user, device)
        assert resp.status_code == 403
        assert json.loads(resp.content)["code"] == "netbox_permission_denied"

    @pytest.mark.parametrize("op", OPS)
    def test_out_of_constraint_object_returns_404(self, op, user, device_b, binding_b):
        """Plugin permissions granted, view_device constrained to Site A, target in Site B → 404."""
        _grant_plugin_perms(user)
        grant_view_device(user, constraints=SITE_A_ONLY)
        resp = self._call(op, user, device_b)
        assert resp.status_code == 404
        expected = "binding_not_found" if op == "delete" else "object_not_found"
        assert json.loads(resp.content)["code"] == expected
        if op in ("detail", "reveal", "copy"):
            assert self.fake.calls == [("require_session",)], "Passwork is never queried for a hidden object"
        if op == "create":
            assert not PassworkBinding.objects.filter(passwork_item_id="pw_created").exists()
        if op == "delete":
            assert PassworkBinding.objects.filter(pk=binding_b.pk).exists(), "the hidden binding is not deleted"

    @pytest.mark.parametrize(
        "op, status",
        [("list", 200), ("detail", 200), ("reveal", 200), ("copy", 200), ("create", 201), ("delete", 200)],
    )
    def test_in_constraint_object_succeeds(self, op, status, user, device, binding_a):
        """The same constrained user succeeds against a Site A device — constraints allow, not just deny."""
        _grant_plugin_perms(user)
        grant_view_device(user, constraints=SITE_A_ONLY)
        resp = self._call(op, user, device)
        assert resp.status_code == status, resp.content
        if op == "reveal":
            assert json.loads(resp.content)["password"] == "s"


@pytest.mark.django_db
class TestOrphanedBindings:
    """ADR-0002: a binding whose object is gone is unreadable, but deletable with the plugin permission alone."""

    def setup_method(self):
        self.factory = RequestFactory()

    def _orphan(self, user):
        return PassworkBinding.objects.create(
            object_type="device", object_id=424242, passwork_item_id="pw_orphan", created_by=user
        )

    def test_orphan_detail_returns_404_even_with_full_view_rights(self, user):
        _grant_plugin_perms(user)
        grant_view_device(user)
        orphan = self._orphan(user)
        request = self.factory.get(
            f"/secrets/{orphan.passwork_item_id}/detail/",
            {"object_type": "device", "object_id": str(orphan.object_id)},
        )
        request.user = user
        request.session = {}
        fake = FakeGateway(get_item=ITEM)
        resp = SecretDetailView.as_view(gateway_factory=lambda r: fake)(request, pw_id=orphan.passwork_item_id)
        assert resp.status_code == 404
        assert json.loads(resp.content)["code"] == "object_not_found"

    def test_orphan_delete_works_with_plugin_permission_alone(self, user):
        """No view_device at all — the orphan must still be deletable, or it becomes garbage forever."""
        grant_netbox_perm(user, "delete_binding")
        orphan = self._orphan(user)
        request = self.factory.delete(f"/bindings/{orphan.pk}/")
        request.user = user
        request.session = {}
        resp = BindingsDeleteView.as_view()(request, binding_id=orphan.pk)
        assert resp.status_code == 200
        assert not PassworkBinding.objects.filter(pk=orphan.pk).exists()


@pytest.mark.django_db
class TestBoundObjectAccess:
    """Unit tests for the gate helper: type mapping and the visible/hidden/missing outcomes."""

    def test_unknown_type_is_missing(self, user):
        assert bound_object_access(user, "router", 1) == "missing"

    @pytest.mark.parametrize("object_type", ["device", "vm", "service"])
    def test_nonexistent_object_is_missing(self, user, object_type):
        assert bound_object_access(user, object_type, 424242) == "missing"

    def test_constraints_split_visible_and_hidden(self, user, device, device_b):
        grant_view_device(user, constraints=SITE_A_ONLY)
        assert bound_object_access(user, "device", device.pk) == "visible"
        assert bound_object_access(user, "device", device_b.pk) == "hidden"

    def test_no_view_permission_at_all_is_hidden(self, user, device):
        assert bound_object_access(user, "device", device.pk) == "hidden"

    def test_superuser_sees_everything(self, device):
        from django.contrib.auth import get_user_model

        root = get_user_model().objects.create_superuser(username="root_matrix", password="x")
        assert bound_object_access(root, "device", device.pk) == "visible"
