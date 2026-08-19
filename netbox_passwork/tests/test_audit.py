import json

import pytest
from django.test import RequestFactory

from netbox_passwork.models import PassworkAuditLog
from netbox_passwork.tests.conftest import grant_netbox_perm
from netbox_passwork.views import AuditLogView


@pytest.mark.django_db
class TestAuditLogView:
    def setup_method(self):
        self.factory = RequestFactory()
        self.view = AuditLogView.as_view()

    def _create_log(self, user, action="reveal"):
        return PassworkAuditLog.objects.create(
            netbox_user=user,
            passwork_item_id="pw_audit_test",
            object_type="device",
            object_id=1,
            action=action,
            ip_address="127.0.0.1",
        )

    def test_requires_view_auditlog_permission(self, user):
        request = self.factory.get("/audit/")
        request.user = user
        assert self.view(request).status_code == 403

    def test_returns_logs_with_permission(self, user):
        grant_netbox_perm(user, "view_auditlog")
        self._create_log(user)
        request = self.factory.get("/audit/")
        request.user = user
        resp = self.view(request)
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data["count"] >= 1

    def test_filter_by_action(self, user):
        grant_netbox_perm(user, "view_auditlog")
        self._create_log(user, "reveal")
        self._create_log(user, "copy")
        request = self.factory.get("/audit/", {"action": "reveal"})
        request.user = user
        resp = self.view(request)
        data = json.loads(resp.content)
        assert all(r["action"] == "reveal" for r in data["results"])

    def test_audit_log_contains_no_passwords(self, user):
        """The log must not contain password values."""
        grant_netbox_perm(user, "view_auditlog")
        self._create_log(user)
        request = self.factory.get("/audit/")
        request.user = user
        resp = self.view(request)
        content = resp.content.decode()
        assert "password" not in content
        assert "secret" not in content.lower() or "pw_audit_test" in content

    def test_invalid_limit_returns_400(self, user):
        """?limit=abc must return 400, not 500."""
        grant_netbox_perm(user, "view_auditlog")
        request = self.factory.get("/audit/", {"limit": "abc"})
        request.user = user
        resp = self.view(request)
        assert resp.status_code == 400
        assert json.loads(resp.content) == {"code": "invalid_param", "detail": "limit and offset must be integers"}

    def test_invalid_offset_returns_400(self, user):
        """?offset=xyz must return 400, not 500."""
        grant_netbox_perm(user, "view_auditlog")
        request = self.factory.get("/audit/", {"offset": "xyz"})
        request.user = user
        resp = self.view(request)
        assert resp.status_code == 400
        assert json.loads(resp.content) == {"code": "invalid_param", "detail": "limit and offset must be integers"}

    def test_negative_offset_treated_as_zero(self, user):
        """A negative offset must be treated as 0."""
        grant_netbox_perm(user, "view_auditlog")
        self._create_log(user)
        request = self.factory.get("/audit/", {"offset": "-99"})
        request.user = user
        resp = self.view(request)
        assert resp.status_code == 200

    def test_negative_limit_returns_400(self, user):
        """?limit=-1 must return 400."""
        grant_netbox_perm(user, "view_auditlog")
        request = self.factory.get("/audit/", {"limit": "-1"})
        request.user = user
        resp = self.view(request)
        assert resp.status_code == 400
        assert json.loads(resp.content) == {"code": "invalid_param", "detail": "limit must be >= 1"}

    def test_invalid_user_filter_returns_400(self, user):
        """?user=not_a_number must return 400, not 500."""
        grant_netbox_perm(user, "view_auditlog")
        request = self.factory.get("/audit/", {"user": "not_a_number"})
        request.user = user
        resp = self.view(request)
        assert resp.status_code == 400
        assert json.loads(resp.content) == {"code": "invalid_param", "detail": "user must be an integer"}
