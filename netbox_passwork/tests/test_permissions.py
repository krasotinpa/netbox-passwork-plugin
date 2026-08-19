import json

import pytest
from django.contrib.auth.models import AnonymousUser
from django.contrib.contenttypes.models import ContentType
from django.http import JsonResponse
from django.test import RequestFactory
from django.views import View

from netbox_passwork.models import PassworkBinding
from netbox_passwork.permissions import RequireNetboxPermMixin, require_netbox_perm


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
