import json
from urllib.parse import urlencode

import pytest
from django.test import RequestFactory

from netbox_passwork.exceptions import (
    PassworkAccessDenied,
    PassworkBadResponse,
    PassworkError,
    PassworkSessionExpired,
    PassworkTimeout,
)
from netbox_passwork.gateway import build_gateway
from netbox_passwork.models import PassworkAuditLog, PassworkBinding
from netbox_passwork.tests.conftest import FakeGateway, grant_netbox_perm, no_passwork_session
from netbox_passwork.views import (
    PassworkLoginView,
    PassworkTotpView,
    PickerFolderContentsView,
    PickerFoldersView,
    PickerSearchView,
    SecretCopyView,
    SecretDetailView,
    SecretsListView,
)


def _never_called(request):
    raise AssertionError("gateway must not be built before the NetBox permission check")


@pytest.mark.django_db
class TestSecretsListView:
    def setup_method(self):
        self.factory = RequestFactory()
        self.view = SecretsListView.as_view()

    def test_unauthenticated_returns_401(self):
        from django.contrib.auth.models import AnonymousUser

        request = self.factory.get("/secrets/", {"object_type": "device", "object_id": "1"})
        request.user = AnonymousUser()
        assert self.view(request).status_code == 401

    def test_no_permission_returns_403(self, user):
        request = self.factory.get("/secrets/", {"object_type": "device", "object_id": "1"})
        request.user = user
        assert self.view(request).status_code == 403

    def test_returns_binding_list(self, user, binding):
        grant_netbox_perm(user, "view_secrets")
        request = self.factory.get("/secrets/", {"object_type": "device", "object_id": "1"})
        request.user = user
        resp = self.view(request)
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert any(item["pw_id"] == "abc123" for item in data)

    @pytest.mark.parametrize(
        "params", [{}, {"object_type": "device"}, {"object_id": "1"}, {"object_type": " ", "object_id": "1"}]
    )
    def test_missing_params_returns_400(self, user, params):
        grant_netbox_perm(user, "view_secrets")
        request = self.factory.get("/secrets/", params)
        request.user = user
        resp = self.view(request)
        assert resp.status_code == 400
        assert json.loads(resp.content) == {
            "code": "missing_params",
            "detail": "object_type and object_id are required",
        }

    def test_invalid_object_id_returns_400(self, user):
        grant_netbox_perm(user, "view_secrets")
        request = self.factory.get("/secrets/", {"object_type": "device", "object_id": "abc"})
        request.user = user
        resp = self.view(request)
        assert resp.status_code == 400
        assert json.loads(resp.content) == {"code": "invalid_object_id", "detail": "object_id must be an integer"}


ITEM = {
    "name": "Test",
    "login": "admin",
    "password": "secret",
    "description": "desc",
    "url": "https://passwork.test/items/abc123",
    "custom_fields": [
        {"name": "port", "is_secret": False, "type": "text", "value": "22"},
        {"name": "pin", "is_secret": True, "type": "password", "value": "0000"},
    ],
}


@pytest.mark.django_db
class TestSecretDetailView:
    """
    GET /secrets/{pw_id}/detail/ via the gateway: FakeGateway is injected through the as_view(gateway_factory=...) seam.

    Order of checks: 401 NetBox → 403 permission (view_secrets, with reveal — reveal_secret) →
    401 Passwork session → 400 parameters → 404 binding → 403/504/502/401 Passwork → audit.
    """

    def setup_method(self):
        self.factory = RequestFactory()

    def _get(self, user, pw_id="abc123", params=None, session=None):
        query = {"object_type": "device", "object_id": "1", **(params or {})}
        request = self.factory.get(f"/secrets/{pw_id}/detail/", query)
        request.user = user
        request.session = session if session is not None else {}
        return request

    def _view(self, fake=None):
        return SecretDetailView.as_view(gateway_factory=lambda request: fake or FakeGateway())

    # --- NetBox permissions: before the gateway ---

    def test_unauthenticated_returns_401_before_gateway(self):
        from django.contrib.auth.models import AnonymousUser

        resp = SecretDetailView.as_view(gateway_factory=_never_called)(self._get(AnonymousUser()), pw_id="abc123")
        assert resp.status_code == 401
        assert json.loads(resp.content)["code"] == "not_authenticated"

    def test_no_view_permission_returns_403_before_gateway(self, user):
        resp = SecretDetailView.as_view(gateway_factory=_never_called)(self._get(user), pw_id="abc123")
        assert resp.status_code == 403
        assert json.loads(resp.content)["code"] == "netbox_permission_denied"

    def test_reveal_without_permission_returns_403_before_session(self, user, binding):
        """view_secrets present, reveal_secret absent → 403 even before touching the Passwork session."""
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(require_session=no_passwork_session())
        resp = self._view(fake)(self._get(user, params={"reveal": "true"}), pw_id="abc123")
        assert resp.status_code == 403
        assert json.loads(resp.content) == {"code": "netbox_permission_denied", "detail": "Permission denied"}
        assert fake.calls == [], "the reveal_secret permission is checked before require_session"

    # --- Passwork session: before parameters and binding ---

    def test_no_passwork_session_returns_401_before_params(self, user):
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(require_session=no_passwork_session())
        resp = self._view(fake)(self._get(user, params={"object_id": "not-int"}), pw_id="abc123")
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"code": "pw_not_authenticated", "detail": "Passwork session not found"}
        assert fake.calls == [("require_session",)], "parameters were not parsed, get_item was not called"

    def test_expired_session_returns_401(self, user, binding):
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(require_session=PassworkSessionExpired())
        resp = self._view(fake)(self._get(user), pw_id="abc123")
        assert resp.status_code == 401
        assert json.loads(resp.content)["code"] == "pw_session_expired"

    # --- parameters and binding: before Passwork ---

    @pytest.mark.parametrize("object_id", ["abc", "", " "])
    def test_invalid_object_id_returns_400(self, user, binding, object_id):
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(get_item=ITEM)
        resp = self._view(fake)(self._get(user, params={"object_id": object_id}), pw_id="abc123")
        assert resp.status_code == 400
        assert json.loads(resp.content) == {"code": "invalid_object_id", "detail": "object_id must be an integer"}
        assert fake.calls == [("require_session",)]

    def test_binding_not_found_returns_404(self, user, binding):
        """pw_id not bound to the object → 404, Passwork is not queried (protection against proxying arbitrary secrets)."""
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(get_item=ITEM)
        resp = self._view(fake)(self._get(user, pw_id="no_such_pw"), pw_id="no_such_pw")
        assert resp.status_code == 404
        assert json.loads(resp.content) == {"code": "binding_not_found", "detail": "Binding not found"}
        assert fake.calls == [("require_session",)]

    def test_binding_of_other_object_returns_404(self, user, binding):
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(get_item=ITEM)
        resp = self._view(fake)(self._get(user, params={"object_id": "2"}), pw_id="abc123")
        assert resp.status_code == 404
        assert fake.calls == [("require_session",)]

    # --- Passwork failures ---

    @pytest.mark.parametrize(
        "exc, status, code",
        [
            (PassworkAccessDenied(), 403, "pw_access_denied"),
            (PassworkTimeout("GET /api/v1/items/abc123 timed out"), 504, "pw_timeout"),
            (PassworkBadResponse(), 502, "pw_bad_response"),
            (PassworkSessionExpired(), 401, "pw_session_expired"),
        ],
    )
    def test_passwork_error_maps_to_status_and_code(self, user, binding, exc, status, code):
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(get_item=exc)
        resp = self._view(fake)(self._get(user), pw_id="abc123")
        assert resp.status_code == status
        assert json.loads(resp.content) == {"code": code, "detail": exc.detail}
        assert fake.calls == [("require_session",), ("get_item", "abc123")]

    # --- success ---

    def test_detail_without_reveal_hides_password_and_secret_fields(self, user, binding):
        grant_netbox_perm(user, "view_secrets")
        grant_netbox_perm(user, "reveal_secret")  # permission present, but reveal was not requested
        fake = FakeGateway(get_item=ITEM)
        resp = self._view(fake)(self._get(user), pw_id="abc123")
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data == {
            "pw_id": "abc123",
            "name": "Test",
            "login": "admin",
            "description": "desc",
            "passwork_url": "https://passwork.test/items/abc123",
            "custom_fields": [
                {"name": "port", "is_secret": False, "type": "text", "value": "22"},
                {"name": "pin", "is_secret": True, "type": "password", "value": ""},
            ],
        }
        assert "password" not in data
        assert not PassworkAuditLog.objects.filter(passwork_item_id="abc123").exists(), "no audit entry without reveal"
        assert fake.calls == [("require_session",), ("get_item", "abc123")]

    def test_reveal_returns_password_and_creates_audit_log(self, user, binding):
        grant_netbox_perm(user, "view_secrets")
        grant_netbox_perm(user, "reveal_secret")
        fake = FakeGateway(get_item=ITEM)
        request = self._get(user, params={"reveal": "true"})
        request.META["REMOTE_ADDR"] = "10.0.0.7"
        resp = self._view(fake)(request, pw_id="abc123")
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data["password"] == "secret"
        assert data["custom_fields"][1]["value"] == "0000", "the secret custom field is revealed"
        log = PassworkAuditLog.objects.get(passwork_item_id="abc123", action="reveal")
        assert (log.netbox_user, log.object_type, log.object_id, log.ip_address) == (user, "device", 1, "10.0.0.7")
        assert fake.calls == [("require_session",), ("get_item", "abc123")]

    def test_reveal_param_is_case_insensitive(self, user, binding):
        grant_netbox_perm(user, "view_secrets")
        grant_netbox_perm(user, "reveal_secret")
        resp = self._view(FakeGateway(get_item=ITEM))(self._get(user, params={"reveal": "TRUE"}), pw_id="abc123")
        assert json.loads(resp.content)["password"] == "secret"

    def test_missing_item_fields_default_to_empty(self, user, binding):
        """Passwork response without fields → empty strings, no KeyError."""
        grant_netbox_perm(user, "view_secrets")
        resp = self._view(FakeGateway(get_item={}))(self._get(user), pw_id="abc123")
        assert resp.status_code == 200
        assert json.loads(resp.content) == {
            "pw_id": "abc123",
            "name": "",
            "login": "",
            "description": "",
            "passwork_url": "",
            "custom_fields": [],
        }

    def test_default_gateway_factory_is_build_gateway(self):
        assert SecretDetailView.gateway_factory is build_gateway
        assert SecretDetailView.permission_required == "view_secrets"


# ---------------------------------------------------------------------------
# Copy
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestSecretCopyView:
    """
    POST /secrets/{pw_id}/copy/ via the gateway: only an audit entry for the copy, but a live Passwork
    session is required (require_session); the secret itself is not requested from Passwork.
    """

    def setup_method(self):
        self.factory = RequestFactory()

    def _post(self, user, pw_id="abc123", params=None):
        query = {"object_type": "device", "object_id": "1", **(params or {})}
        request = self.factory.post(f"/secrets/{pw_id}/copy/?{urlencode(query)}")
        request.user = user
        request.session = {}
        return request

    def _view(self, fake=None):
        return SecretCopyView.as_view(gateway_factory=lambda request: fake or FakeGateway())

    def test_unauthenticated_returns_401_before_gateway(self):
        from django.contrib.auth.models import AnonymousUser

        resp = SecretCopyView.as_view(gateway_factory=_never_called)(self._post(AnonymousUser()), pw_id="abc123")
        assert resp.status_code == 401

    def test_no_reveal_permission_returns_403_before_gateway(self, user, binding):
        grant_netbox_perm(user, "view_secrets")  # view_secrets is not enough — reveal_secret is needed
        resp = SecretCopyView.as_view(gateway_factory=_never_called)(self._post(user), pw_id="abc123")
        assert resp.status_code == 403
        assert json.loads(resp.content)["code"] == "netbox_permission_denied"

    def test_no_passwork_session_returns_401_before_params(self, user, binding):
        grant_netbox_perm(user, "reveal_secret")
        fake = FakeGateway(require_session=no_passwork_session())
        resp = self._view(fake)(self._post(user, params={"object_id": "x"}), pw_id="abc123")
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"code": "pw_not_authenticated", "detail": "Passwork session not found"}
        assert fake.calls == [("require_session",)]
        assert not PassworkAuditLog.objects.filter(action="copy").exists()

    def test_invalid_object_id_returns_400(self, user, binding):
        grant_netbox_perm(user, "reveal_secret")
        resp = self._view()(self._post(user, params={"object_id": "x"}), pw_id="abc123")
        assert resp.status_code == 400
        assert json.loads(resp.content) == {"code": "invalid_object_id", "detail": "object_id must be an integer"}

    def test_binding_not_found_returns_404(self, user, binding):
        grant_netbox_perm(user, "reveal_secret")
        fake = FakeGateway()
        resp = self._view(fake)(self._post(user, pw_id="no_such_pw"), pw_id="no_such_pw")
        assert resp.status_code == 404
        assert json.loads(resp.content) == {"code": "binding_not_found", "detail": "Binding not found"}
        assert not PassworkAuditLog.objects.filter(action="copy").exists()

    def test_copy_creates_audit_log(self, user, binding):
        grant_netbox_perm(user, "reveal_secret")
        fake = FakeGateway()
        request = self._post(user)
        request.META["REMOTE_ADDR"] = "10.0.0.7"
        resp = self._view(fake)(request, pw_id="abc123")
        assert resp.status_code == 200
        assert json.loads(resp.content) == {"status": "ok"}
        log = PassworkAuditLog.objects.get(passwork_item_id="abc123", action="copy")
        assert (log.netbox_user, log.object_type, log.object_id, log.ip_address) == (user, "device", 1, "10.0.0.7")
        assert fake.calls == [("require_session",)], "copy only checks the session, it does not call get_item"

    def test_default_gateway_factory_is_build_gateway(self):
        assert SecretCopyView.gateway_factory is build_gateway
        assert SecretCopyView.permission_required == "reveal_secret"


# ---------------------------------------------------------------------------
# Login / TOTP
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestPassworkLoginView:
    """POST /auth/login/ via the gateway: FakeGateway is injected through the as_view(gateway_factory=...) seam."""

    def setup_method(self):
        self.factory = RequestFactory()

    def _post(self, user, body):
        request = self.factory.post(
            "/auth/login/",
            data=body if isinstance(body, str) else json.dumps(body),
            content_type="application/json",
        )
        request.user = user
        request.session = {}
        return request

    def _view(self, fake=None):
        return PassworkLoginView.as_view(gateway_factory=lambda request: fake or FakeGateway())

    def test_unauthenticated_returns_401_before_gateway(self):
        from django.contrib.auth.models import AnonymousUser

        def never_called(request):
            raise AssertionError("gateway must not be built before the NetBox authentication check")

        resp = PassworkLoginView.as_view(gateway_factory=never_called)(self._post(AnonymousUser(), {}))
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"detail": "Authentication required", "code": "not_authenticated"}

    def test_no_netbox_permission_required(self, user):
        """permission_required = None: an authenticated user without plugin permissions passes."""
        fake = FakeGateway(login=False)
        resp = self._view(fake)(self._post(user, {"username": "u", "password": "p"}))
        assert resp.status_code == 200

    def test_invalid_json_returns_400(self, user):
        fake = FakeGateway()
        resp = self._view(fake)(self._post(user, "{not json"))
        assert resp.status_code == 400
        body = json.loads(resp.content)
        assert set(body) == {"code", "detail"}
        assert body["code"] == "invalid_json"
        assert fake.calls == [], "the gateway was not called with an invalid body"

    def test_non_object_json_returns_400(self, user):
        resp = self._view()(self._post(user, "[1, 2]"))
        assert resp.status_code == 400
        assert json.loads(resp.content)["code"] == "invalid_json"

    def test_missing_credentials_returns_400(self, user):
        fake = FakeGateway()
        resp = self._view(fake)(self._post(user, {"username": "", "password": ""}))
        assert resp.status_code == 400
        body = json.loads(resp.content)
        assert set(body) == {"code", "detail"}
        assert body["code"] == "missing_credentials"
        assert fake.calls == []

    def test_non_string_credentials_returns_400(self, user):
        fake = FakeGateway()
        resp = self._view(fake)(self._post(user, {"username": None, "password": 123}))
        assert resp.status_code == 400
        assert json.loads(resp.content)["code"] == "missing_credentials"
        assert fake.calls == []

    def test_invalid_credentials_returns_401(self, user):
        fake = FakeGateway(
            login=PassworkAccessDenied("Invalid credentials", code="invalid_credentials", http_status=401)
        )
        resp = self._view(fake)(self._post(user, {"username": "u", "password": "wrong"}))
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"code": "invalid_credentials", "detail": "Invalid credentials"}

    def test_successful_login_no_totp(self, user):
        fake = FakeGateway(login=False)
        resp = self._view(fake)(self._post(user, {"username": "u", "password": "p"}))
        assert resp.status_code == 200
        assert json.loads(resp.content) == {"status": "ok", "requires_totp": False}
        # requires_passwork_session = False: the session is not checked, only login
        assert fake.calls == [("login", "u", "p")]

    def test_successful_login_totp_required(self, user):
        fake = FakeGateway(login=True)
        resp = self._view(fake)(self._post(user, {"username": "u", "password": "p"}))
        assert resp.status_code == 200
        assert json.loads(resp.content) == {"status": "totp_required", "requires_totp": True}

    def test_credentials_are_stripped(self, user):
        fake = FakeGateway(login=False)
        self._view(fake)(self._post(user, {"username": "  u  ", "password": " p "}))
        assert fake.calls == [("login", "u", "p")]

    def test_timeout_returns_504(self, user):
        fake = FakeGateway(login=PassworkTimeout("POST /api/v1/users/login timed out"))
        resp = self._view(fake)(self._post(user, {"username": "u", "password": "p"}))
        assert resp.status_code == 504
        assert json.loads(resp.content) == {"code": "pw_timeout", "detail": "POST /api/v1/users/login timed out"}

    def test_bad_response_returns_502(self, user):
        fake = FakeGateway(login=PassworkBadResponse())
        resp = self._view(fake)(self._post(user, {"username": "u", "password": "p"}))
        assert resp.status_code == 502
        body = json.loads(resp.content)
        assert set(body) == {"code", "detail"}
        assert body["code"] == "pw_bad_response"

    def test_default_gateway_factory_is_build_gateway(self):
        assert PassworkLoginView.gateway_factory is build_gateway
        assert PassworkLoginView.requires_passwork_session is False
        assert PassworkLoginView.permission_required is None


@pytest.mark.django_db
class TestPassworkTotpView:
    """POST /auth/totp/ via the gateway: the Passwork session is checked by the base view before parsing the body."""

    def setup_method(self):
        self.factory = RequestFactory()

    def _post(self, user, body):
        request = self.factory.post(
            "/auth/totp/",
            data=body if isinstance(body, str) else json.dumps(body),
            content_type="application/json",
        )
        request.user = user
        request.session = {}
        return request

    def _view(self, fake=None):
        return PassworkTotpView.as_view(gateway_factory=lambda request: fake or FakeGateway())

    def test_unauthenticated_returns_401(self):
        from django.contrib.auth.models import AnonymousUser

        resp = self._view()(self._post(AnonymousUser(), {"code": "123456"}))
        assert resp.status_code == 401
        assert json.loads(resp.content)["code"] == "not_authenticated"

    def test_no_session_returns_401_before_body(self, user):
        fake = FakeGateway(
            require_session=PassworkError("Passwork session not found", code="pw_not_authenticated", http_status=401)
        )
        resp = self._view(fake)(self._post(user, "{not json"))
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"code": "pw_not_authenticated", "detail": "Passwork session not found"}
        assert fake.calls == [("require_session",)], "the body was not parsed, confirm_totp was not called"

    def test_expired_session_returns_401(self, user):
        fake = FakeGateway(require_session=PassworkSessionExpired())
        resp = self._view(fake)(self._post(user, {"code": "123456"}))
        assert resp.status_code == 401
        assert json.loads(resp.content)["code"] == "pw_session_expired"

    def test_invalid_json_returns_400(self, user):
        fake = FakeGateway()
        resp = self._view(fake)(self._post(user, "{not json"))
        assert resp.status_code == 400
        body = json.loads(resp.content)
        assert set(body) == {"code", "detail"}
        assert body["code"] == "invalid_json"
        assert fake.calls == [("require_session",)]

    def test_missing_code_returns_400(self, user):
        fake = FakeGateway()
        resp = self._view(fake)(self._post(user, {"code": "  "}))
        assert resp.status_code == 400
        body = json.loads(resp.content)
        assert set(body) == {"code", "detail"}
        assert body["code"] == "missing_code"
        assert fake.calls == [("require_session",)]

    def test_non_string_code_returns_400(self, user):
        fake = FakeGateway()
        resp = self._view(fake)(self._post(user, {"code": 123456}))
        assert resp.status_code == 400
        assert json.loads(resp.content)["code"] == "missing_code"
        assert fake.calls == [("require_session",)]

    def test_invalid_totp_returns_401(self, user):
        fake = FakeGateway(
            confirm_totp=PassworkAccessDenied("Invalid TOTP code", code="invalid_totp", http_status=401)
        )
        resp = self._view(fake)(self._post(user, {"code": "000000"}))
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"code": "invalid_totp", "detail": "Invalid TOTP code"}

    def test_valid_totp_returns_ok(self, user):
        fake = FakeGateway()
        resp = self._view(fake)(self._post(user, {"code": " 123456 "}))
        assert resp.status_code == 200
        assert json.loads(resp.content) == {"status": "ok"}
        assert fake.calls == [("require_session",), ("confirm_totp", "123456")]

    def test_totp_timeout_returns_504(self, user):
        fake = FakeGateway(confirm_totp=PassworkTimeout("Passwork did not respond"))
        resp = self._view(fake)(self._post(user, {"code": "123456"}))
        assert resp.status_code == 504
        assert json.loads(resp.content) == {"code": "pw_timeout", "detail": "Passwork did not respond"}

    def test_totp_bad_response_returns_502(self, user):
        fake = FakeGateway(confirm_totp=PassworkBadResponse())
        resp = self._view(fake)(self._post(user, {"code": "123456"}))
        assert resp.status_code == 502
        assert json.loads(resp.content)["code"] == "pw_bad_response"

    def test_default_gateway_factory_is_build_gateway(self):
        assert PassworkTotpView.gateway_factory is build_gateway
        assert PassworkTotpView.requires_passwork_session is True
        assert PassworkTotpView.permission_required is None


# ---------------------------------------------------------------------------
# Bindings create / delete
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestBindingsCreateView:
    def setup_method(self):
        self.factory = RequestFactory()
        from netbox_passwork.views import BindingsCreateView

        self.view = BindingsCreateView.as_view()

    def _post(self, user, body):
        request = self.factory.post(
            "/bindings/",
            data=json.dumps(body),
            content_type="application/json",
        )
        request.user = user
        request.session = {}
        return request

    def test_no_permission_returns_403(self, user):
        request = self._post(user, {})
        assert self.view(request).status_code == 403

    def test_missing_params_returns_400(self, user):
        grant_netbox_perm(user, "add_binding")
        request = self._post(user, {"object_type": "device"})
        resp = self.view(request)
        assert resp.status_code == 400
        assert json.loads(resp.content) == {
            "code": "missing_params",
            "detail": "object_type, object_id and passwork_item_id are required",
        }

    @pytest.mark.parametrize("raw", ["not json", "[1, 2]", '"str"'])
    def test_invalid_json_returns_400(self, user, raw):
        """Not JSON or JSON that is not an object → 400 invalid_json (not 500)."""
        grant_netbox_perm(user, "add_binding")
        request = self.factory.post("/bindings/", data=raw, content_type="application/json")
        request.user = user
        request.session = {}
        resp = self.view(request)
        assert resp.status_code == 400
        assert json.loads(resp.content) == {"code": "invalid_json", "detail": "Request body must be a JSON object"}

    def test_non_string_fields_are_missing_params(self, user):
        """object_type/passwork_item_id not strings → 400 missing_params (not 500 on .strip())."""
        grant_netbox_perm(user, "add_binding")
        request = self._post(user, {"object_type": 1, "object_id": 1, "passwork_item_id": ["x"]})
        resp = self.view(request)
        assert resp.status_code == 400
        assert json.loads(resp.content)["code"] == "missing_params"

    def test_creates_binding(self, user):
        grant_netbox_perm(user, "add_binding")
        request = self._post(
            user,
            {
                "object_type": "device",
                "object_id": 99,
                "passwork_item_id": "pw_new",
            },
        )
        resp = self.view(request)
        assert resp.status_code == 201
        assert PassworkBinding.objects.filter(passwork_item_id="pw_new").exists()

    def test_duplicate_returns_409(self, user, binding):
        grant_netbox_perm(user, "add_binding")
        request = self._post(
            user,
            {
                "object_type": "device",
                "object_id": 1,
                "passwork_item_id": "abc123",
            },
        )
        resp = self.view(request)
        assert resp.status_code == 409
        assert json.loads(resp.content) == {"code": "duplicate_binding", "detail": "Binding already exists"}

    def test_invalid_object_type_returns_400(self, user):
        """object_type not in the allowed list → 400."""
        grant_netbox_perm(user, "add_binding")
        request = self._post(
            user,
            {
                "object_type": "router",  # not device / vm / service
                "object_id": 1,
                "passwork_item_id": "pw_001",
            },
        )
        resp = self.view(request)
        assert resp.status_code == 400
        assert json.loads(resp.content) == {
            "code": "invalid_object_type",
            "detail": "object_type must be one of: device, vm, service",
        }


@pytest.mark.django_db
class TestBindingsDeleteView:
    def setup_method(self):
        self.factory = RequestFactory()
        from netbox_passwork.views import BindingsDeleteView

        self.view = BindingsDeleteView.as_view()

    def test_no_permission_returns_403(self, user, binding):
        request = self.factory.delete(f"/bindings/{binding.pk}/")
        request.user = user
        request.session = {}
        assert self.view(request, binding_id=binding.pk).status_code == 403

    def test_not_found_returns_404(self, user):
        grant_netbox_perm(user, "delete_binding")
        request = self.factory.delete("/bindings/99999/")
        request.user = user
        request.session = {}
        resp = self.view(request, binding_id=99999)
        assert resp.status_code == 404
        assert json.loads(resp.content) == {"code": "binding_not_found", "detail": "Binding not found"}

    def test_deletes_binding(self, user, binding):
        grant_netbox_perm(user, "delete_binding")
        request = self.factory.delete(f"/bindings/{binding.pk}/")
        request.user = user
        request.session = {}
        resp = self.view(request, binding_id=binding.pk)
        assert resp.status_code == 200
        assert not PassworkBinding.objects.filter(pk=binding.pk).exists()


# ---------------------------------------------------------------------------
# Picker
# ---------------------------------------------------------------------------

VAULTS = [{"id": "v1", "name": "Vault1"}, {"id": "v2", "name": "Vault2"}]
FOUND = [{"id": "pw1", "name": "Router", "login": "admin"}]

# Passwork failures during picking (shared by folders and search): exception → response status and code
PASSWORK_FAILURES = [
    (PassworkSessionExpired(), 401, "pw_session_expired"),
    (PassworkAccessDenied(), 403, "pw_access_denied"),
    (PassworkTimeout(), 504, "pw_timeout"),
    (PassworkBadResponse(), 502, "pw_bad_response"),
]


@pytest.mark.django_db
class TestPickerFoldersView:
    """
    GET /picker/folders/ via the gateway: 401 NetBox → 403 permission add_binding → 401 Passwork session →
    list_vaults. Passwork failures — {"code","detail"} with the status from the exception (401/403 instead
    of the former 200 with an empty list); the successful body is an array of vaults as before.
    """

    def setup_method(self):
        self.factory = RequestFactory()

    def _get(self, user):
        request = self.factory.get("/picker/folders/")
        request.user = user
        request.session = {}
        return request

    def _view(self, fake=None):
        return PickerFoldersView.as_view(gateway_factory=lambda request: fake or FakeGateway())

    def test_unauthenticated_returns_401_before_gateway(self):
        from django.contrib.auth.models import AnonymousUser

        resp = PickerFoldersView.as_view(gateway_factory=_never_called)(self._get(AnonymousUser()))
        assert resp.status_code == 401
        assert json.loads(resp.content)["code"] == "not_authenticated"

    def test_no_permission_returns_403_before_gateway(self, user):
        resp = PickerFoldersView.as_view(gateway_factory=_never_called)(self._get(user))
        assert resp.status_code == 403
        assert json.loads(resp.content)["code"] == "netbox_permission_denied"

    def test_no_passwork_session_returns_401(self, user):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(require_session=no_passwork_session())
        resp = self._view(fake)(self._get(user))
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"code": "pw_not_authenticated", "detail": "Passwork session not found"}
        assert fake.calls == [("require_session",)], "list_vaults was not called"

    @pytest.mark.parametrize("exc, status, code", PASSWORK_FAILURES)
    def test_passwork_error_maps_to_status_and_code(self, user, exc, status, code):
        """401/403 Passwork during picking → HTTP 401/403 (not 200 with an empty list), 504/502 — as before."""
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(list_vaults=exc)
        resp = self._view(fake)(self._get(user))
        assert resp.status_code == status
        assert json.loads(resp.content) == {"code": code, "detail": exc.detail}
        assert fake.calls == [("require_session",), ("list_vaults",)]

    def test_returns_vaults_unchanged(self, user):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(list_vaults=VAULTS)
        resp = self._view(fake)(self._get(user))
        assert resp.status_code == 200
        assert json.loads(resp.content) == VAULTS, "the successful body is an array of vaults with no wrapper"
        assert fake.calls == [("require_session",), ("list_vaults",)]

    def test_no_vaults_returns_empty_list(self, user):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(list_vaults=[])
        resp = self._view(fake)(self._get(user))
        assert resp.status_code == 200
        assert json.loads(resp.content) == []
        assert fake.calls == [("require_session",), ("list_vaults",)]

    def test_default_gateway_factory_is_build_gateway(self):
        assert PickerFoldersView.gateway_factory is build_gateway
        assert PickerFoldersView.permission_required == "add_binding"
        assert PickerFoldersView.requires_passwork_session is True


@pytest.mark.django_db
class TestPickerSearchView:
    """
    GET /picker/search/?q=... via the gateway: 401 NetBox → 403 permission add_binding → 401 Passwork session →
    400 missing_query → search_items(q). URL-encoding the query is the client's concern (H1, test_auth.py):
    the view passes the string to the gateway verbatim.
    """

    def setup_method(self):
        self.factory = RequestFactory()

    def _get(self, user, params=None):
        request = self.factory.get("/picker/search/", params if params is not None else {"q": "router"})
        request.user = user
        request.session = {}
        return request

    def _view(self, fake=None):
        return PickerSearchView.as_view(gateway_factory=lambda request: fake or FakeGateway())

    def test_unauthenticated_returns_401_before_gateway(self):
        from django.contrib.auth.models import AnonymousUser

        resp = PickerSearchView.as_view(gateway_factory=_never_called)(self._get(AnonymousUser()))
        assert resp.status_code == 401
        assert json.loads(resp.content)["code"] == "not_authenticated"

    def test_no_permission_returns_403_before_gateway(self, user):
        resp = PickerSearchView.as_view(gateway_factory=_never_called)(self._get(user))
        assert resp.status_code == 403
        assert json.loads(resp.content)["code"] == "netbox_permission_denied"

    def test_no_passwork_session_returns_401_before_params(self, user):
        """Without a Passwork session — 401 even before parsing q (order of checks: session → parameters)."""
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(require_session=no_passwork_session())
        resp = self._view(fake)(self._get(user, params={}))
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"code": "pw_not_authenticated", "detail": "Passwork session not found"}
        assert fake.calls == [("require_session",)]

    @pytest.mark.parametrize("params", [{}, {"q": ""}, {"q": "   "}])
    def test_missing_query_returns_400(self, user, params):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(search_items=FOUND)
        resp = self._view(fake)(self._get(user, params=params))
        assert resp.status_code == 400
        assert json.loads(resp.content) == {"code": "missing_query", "detail": "Query parameter q is required"}
        assert fake.calls == [("require_session",)], "search_items was not called"

    @pytest.mark.parametrize("exc, status, code", PASSWORK_FAILURES)
    def test_passwork_error_maps_to_status_and_code(self, user, exc, status, code):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(search_items=exc)
        resp = self._view(fake)(self._get(user))
        assert resp.status_code == status
        assert json.loads(resp.content) == {"code": code, "detail": exc.detail}
        assert fake.calls == [("require_session",), ("search_items", "router")]

    def test_returns_found_items_unchanged(self, user):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(search_items=FOUND)
        resp = self._view(fake)(self._get(user))
        assert resp.status_code == 200
        assert json.loads(resp.content) == FOUND, "the successful body is an array of items with no wrapper"
        assert fake.calls == [("require_session",), ("search_items", "router")]

    def test_query_is_stripped_and_passed_verbatim(self, user):
        """Leading/trailing whitespace is trimmed, the rest (including `&`, `=`) goes to the gateway verbatim — the client encodes it."""
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(search_items=[])
        resp = self._view(fake)(self._get(user, params={"q": "  test&perPage=9999 "}))
        assert resp.status_code == 200
        assert fake.calls == [("require_session",), ("search_items", "test&perPage=9999")]

    def test_default_gateway_factory_is_build_gateway(self):
        assert PickerSearchView.gateway_factory is build_gateway
        assert PickerSearchView.permission_required == "add_binding"
        assert PickerSearchView.requires_passwork_session is True


CONTENTS = {"folders": [{"id": "f1", "name": "Network"}], "items": FOUND}


@pytest.mark.django_db
class TestPickerFolderContentsView:
    """
    GET /picker/folders/<vault_id>/items/[?folder_id=...] via the gateway: 401 NetBox → 403 permission
    add_binding → 401 Passwork session → list_folder_contents(vault_id, folder_id). The successful body is
    {"folders": [...], "items": [...]}; Passwork failures — {"code","detail"} with the status from the exception.
    """

    def setup_method(self):
        self.factory = RequestFactory()

    def _get(self, user, params=None):
        query = f"?{urlencode(params)}" if params else ""
        request = self.factory.get(f"/picker/folders/v1/items/{query}")
        request.user = user
        request.session = {}
        return request

    def _view(self, fake=None):
        return PickerFolderContentsView.as_view(gateway_factory=lambda request: fake or FakeGateway())

    def test_unauthenticated_returns_401_before_gateway(self):
        from django.contrib.auth.models import AnonymousUser

        resp = PickerFolderContentsView.as_view(gateway_factory=_never_called)(
            self._get(AnonymousUser()), vault_id="v1"
        )
        assert resp.status_code == 401
        assert json.loads(resp.content)["code"] == "not_authenticated"

    def test_no_permission_returns_403_before_gateway(self, user):
        resp = PickerFolderContentsView.as_view(gateway_factory=_never_called)(self._get(user), vault_id="v1")
        assert resp.status_code == 403
        assert json.loads(resp.content)["code"] == "netbox_permission_denied"

    def test_no_passwork_session_returns_401(self, user):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(require_session=no_passwork_session())
        resp = self._view(fake)(self._get(user), vault_id="v1")
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"code": "pw_not_authenticated", "detail": "Passwork session not found"}
        assert fake.calls == [("require_session",)], "list_folder_contents was not called"

    @pytest.mark.parametrize("exc, status, code", PASSWORK_FAILURES)
    def test_passwork_error_maps_to_status_and_code(self, user, exc, status, code):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(list_folder_contents=exc)
        resp = self._view(fake)(self._get(user), vault_id="v1")
        assert resp.status_code == status
        assert json.loads(resp.content) == {"code": code, "detail": exc.detail}
        assert fake.calls == [("require_session",), ("list_folder_contents", "v1", None)]

    def test_vault_node_returns_contents(self, user):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(list_folder_contents=CONTENTS)
        resp = self._view(fake)(self._get(user), vault_id="v1")
        assert resp.status_code == 200
        assert json.loads(resp.content) == CONTENTS
        assert fake.calls == [("require_session",), ("list_folder_contents", "v1", None)]

    def test_folder_id_is_passed_to_the_gateway(self, user):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(list_folder_contents=CONTENTS)
        resp = self._view(fake)(self._get(user, params={"folder_id": "f1"}), vault_id="v1")
        assert resp.status_code == 200
        assert fake.calls == [("require_session",), ("list_folder_contents", "v1", "f1")]

    @pytest.mark.parametrize("params", [{}, {"folder_id": ""}, {"folder_id": "   "}])
    def test_blank_folder_id_means_vault_node(self, user, params):
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(list_folder_contents=CONTENTS)
        resp = self._view(fake)(self._get(user, params=params), vault_id="v1")
        assert resp.status_code == 200
        assert fake.calls == [("require_session",), ("list_folder_contents", "v1", None)]

    def test_default_gateway_factory_is_build_gateway(self):
        assert PickerFolderContentsView.gateway_factory is build_gateway
        assert PickerFolderContentsView.permission_required == "add_binding"
        assert PickerFolderContentsView.requires_passwork_session is True
