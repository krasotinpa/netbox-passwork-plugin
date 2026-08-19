"""
Phase 7: Security hardening tests
"""

import json

import pytest
from django.test import RequestFactory

from netbox_passwork.models import PassworkAuditLog
from netbox_passwork.tests.conftest import FakeGateway, grant_netbox_perm
from netbox_passwork.views import AuditLogView, SecretDetailView

ITEM = {"name": "T", "login": "u", "password": "SECRET123", "custom_fields": [], "description": "", "url": ""}


@pytest.mark.django_db
class TestSecurityHardening:
    def setup_method(self):
        self.factory = RequestFactory()
        self.audit_view = AuditLogView.as_view()

    def _detail(self, fake, user, pw_id, params):
        request = self.factory.get(f"/secrets/{pw_id}/detail/", params)
        request.user = user
        request.session = {}
        return SecretDetailView.as_view(gateway_factory=lambda request: fake)(request, pw_id=pw_id)

    def test_arbitrary_pw_id_blocked(self, user, binding):
        """pw_id not from a binding → 404, the proxy must not proxy arbitrary secrets."""
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(get_item=ITEM)
        resp = self._detail(fake, user, "HACKER_ID", {"object_type": "device", "object_id": "1"})
        assert resp.status_code == 404
        # get_item must never be called for an unbound pw_id
        assert ("get_item", "HACKER_ID") not in fake.calls

    def test_audit_log_contains_no_passwords(self, user):
        """AuditLog does not contain password values."""
        grant_netbox_perm(user, "view_auditlog")
        PassworkAuditLog.objects.create(
            netbox_user=user,
            passwork_item_id="pw_sec_test",
            object_type="device",
            object_id=1,
            action="reveal",
            ip_address="127.0.0.1",
        )
        request = self.factory.get("/audit/")
        request.user = user
        resp = self.audit_view(request)
        content = resp.content.decode()

        # Password fields must not end up in the response
        assert "password" not in content
        assert "access_token" not in content
        assert "refresh_token" not in content

    def test_reveal_requires_explicit_param(self, user, binding):
        """Without reveal=true the password is not returned, even with reveal_secret permission."""
        grant_netbox_perm(user, "view_secrets")
        grant_netbox_perm(user, "reveal_secret")
        resp = self._detail(FakeGateway(get_item=ITEM), user, "abc123", {"object_type": "device", "object_id": "1"})
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert "password" not in data
        assert "SECRET123" not in resp.content.decode()

    def test_audit_log_only_with_permission(self, user):
        """AuditLog is accessible only with view_auditlog."""
        # WITHOUT the permission
        request = self.factory.get("/audit/")
        request.user = user
        resp = self.audit_view(request)
        assert resp.status_code == 403
