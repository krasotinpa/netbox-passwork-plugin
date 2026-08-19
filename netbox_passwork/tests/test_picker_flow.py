"""
Phase 7.2: Picker flow — login → picker (vaults / search) → create binding → check in DB.

The picker goes through the Passwork gateway: in view tests — ``FakeGateway`` (the
``as_view(gateway_factory=...)`` seam), in the end-to-end scenario — the real ``build_gateway``
and Passwork on ``responses``.
"""

import json
from urllib.parse import parse_qs, urlsplit

import pytest
import responses as resp_mock
from cryptography.fernet import Fernet
from django.test import RequestFactory, override_settings

from netbox_passwork.exceptions import PassworkSessionExpired
from netbox_passwork.models import PassworkBinding
from netbox_passwork.tests.conftest import (
    PASSWORK_URL,
    FakeGateway,
    grant_netbox_perm,
    mock_passwork_login,
    wrap_passwork_response,
)
from netbox_passwork.views import (
    BindingsCreateView,
    BindingsDeleteView,
    PassworkLoginView,
    PickerFoldersView,
    PickerSearchView,
)

VAULTS = [{"id": "v1", "name": "Infra"}]
FOUND = [{"id": "pw_new_001", "name": "Core Router", "login": "admin"}]


@pytest.mark.django_db
class TestPickerFlow:
    def setup_method(self):
        self.factory = RequestFactory()
        self.create_view = BindingsCreateView.as_view()
        self.delete_view = BindingsDeleteView.as_view()

    def _get(self, path, user, params=None):
        request = self.factory.get(path, params or {})
        request.user = user
        request.session = {}
        return request

    def _post_binding(self, user, body):
        request = self.factory.post("/bindings/", data=json.dumps(body), content_type="application/json")
        request.user = user
        request.session = {}
        return self.create_view(request)

    def test_expired_passwork_session_in_picker_returns_401(self, user):
        """Expired Passwork session in the picker modal → 401 pw_session_expired, not 200 with an empty list."""
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(require_session=PassworkSessionExpired())
        resp = PickerFoldersView.as_view(gateway_factory=lambda request: fake)(self._get("/picker/folders/", user))
        assert resp.status_code == 401
        assert json.loads(resp.content) == {"code": "pw_session_expired", "detail": "Passwork session expired"}
        assert fake.calls == [("require_session",)]

    def test_search_then_create_binding_saves_to_db(self, user):
        """Search via the gateway → chosen pw_id → POST /bindings/ creates a binding in the DB."""
        grant_netbox_perm(user, "add_binding")
        fake = FakeGateway(search_items=FOUND)
        resp = PickerSearchView.as_view(gateway_factory=lambda request: fake)(
            self._get("/picker/search/", user, {"q": "core"})
        )
        assert resp.status_code == 200
        found = json.loads(resp.content)
        assert found == FOUND
        assert fake.calls == [("require_session",), ("search_items", "core")]

        resp = self._post_binding(user, {"object_type": "device", "object_id": 42, "passwork_item_id": found[0]["id"]})
        assert resp.status_code == 201

        binding = PassworkBinding.objects.get(passwork_item_id="pw_new_001")
        assert binding.object_type == "device"
        assert binding.object_id == 42
        assert binding.created_by == user

    def test_duplicate_binding_returns_409(self, user, binding):
        """Re-binding the same pw_id → 409."""
        grant_netbox_perm(user, "add_binding")
        resp = self._post_binding(user, {"object_type": "device", "object_id": 1, "passwork_item_id": "abc123"})
        assert resp.status_code == 409
        assert json.loads(resp.content)["code"] == "duplicate_binding"

    def test_delete_binding(self, user, binding):
        """DELETE /bindings/{id}/ removes the binding from the DB."""
        grant_netbox_perm(user, "delete_binding")
        request = self.factory.delete(f"/bindings/{binding.pk}/")
        request.user = user
        request.session = {}
        resp = self.delete_view(request, binding_id=binding.pk)
        assert resp.status_code == 200

        assert not PassworkBinding.objects.filter(pk=binding.pk).exists()

    def test_rebind_after_delete(self, user, binding):
        """After deletion the same pw_id can be bound again."""
        grant_netbox_perm(user, "add_binding")

        binding.delete()

        resp = self._post_binding(user, {"object_type": "device", "object_id": 1, "passwork_item_id": "abc123"})
        assert resp.status_code == 201


# ---------------------------------------------------------------------------
# End-to-end scenario (#16): login via the gateway → vaults and search via the gateway, real build_gateway
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestLoginThenPickerViaGateway:
    """
    One real gateway (``build_gateway``, Passwork — ``responses``) for the whole scenario:
    login stores the Passwork session in the Django session, folders/search read it from there
    (Bearer/CSRF from the stored record), a Passwork 401 reaches the client as 401.
    """

    PLUGIN_CONFIG = {
        "netbox_passwork": {
            "PASSWORK_URL": PASSWORK_URL,
            "PASSWORK_VERIFY_SSL": False,
            "SESSION_ENCRYPT_KEY": Fernet.generate_key(),
        }
    }

    def setup_method(self):
        self.factory = RequestFactory()
        self.session = {}  # a single "Django session" for all requests in the scenario

    def _login(self, user):
        request = self.factory.post(
            "/auth/login/", data=json.dumps({"username": "u", "password": "p"}), content_type="application/json"
        )
        request.user = user
        request.session = self.session
        return PassworkLoginView.as_view()(request)

    def _get(self, view_class, path, user, params=None):
        request = self.factory.get(path, params or {})
        request.user = user
        request.session = self.session
        return view_class.as_view()(request)

    @resp_mock.activate
    def test_login_then_folders_and_search(self, user):
        grant_netbox_perm(user, "add_binding")
        mock_passwork_login()
        resp_mock.add(resp_mock.GET, f"{PASSWORK_URL}/api/v1/vaults", json=wrap_passwork_response({"items": VAULTS}))
        resp_mock.add(
            resp_mock.GET, f"{PASSWORK_URL}/api/v1/items/search", json=wrap_passwork_response({"items": FOUND})
        )

        with override_settings(PLUGINS_CONFIG=self.PLUGIN_CONFIG):
            assert self._login(user).status_code == 200
            assert "pw_session" in self.session, "the gateway wrote the Passwork session into the Django session"

            resp = self._get(PickerFoldersView, "/picker/folders/", user)
            assert resp.status_code == 200, resp.content
            assert json.loads(resp.content) == VAULTS
            vaults_call = resp_mock.calls[-1].request
            assert vaults_call.headers["Authorization"] == "Bearer acc1", "folders read the tokens saved by login"
            assert vaults_call.headers["X-CSRF-Token"] == "csrf2"

            resp = self._get(PickerSearchView, "/picker/search/", user, {"q": "core router&perPage=9999"})

        assert resp.status_code == 200, resp.content
        assert json.loads(resp.content) == FOUND
        search_call = resp_mock.calls[-1].request
        assert search_call.headers["Authorization"] == "Bearer acc1"
        assert parse_qs(urlsplit(search_call.url).query) == {"query": ["core router&perPage=9999"]}, (
            "the request reached Passwork as a single URL-encoded parameter (H1)"
        )

    @resp_mock.activate
    def test_passwork_401_in_picker_maps_to_session_expired(self, user):
        """Real chain: Passwork 401 on /api/v1/vaults → PassworkSessionExpired → gateway → PassworkView → 401."""
        grant_netbox_perm(user, "add_binding")
        mock_passwork_login()
        resp_mock.add(
            resp_mock.GET, f"{PASSWORK_URL}/api/v1/vaults", json=wrap_passwork_response({"errors": []}), status=401
        )

        with override_settings(PLUGINS_CONFIG=self.PLUGIN_CONFIG):
            self._login(user)
            resp = self._get(PickerFoldersView, "/picker/folders/", user)

        assert resp.status_code == 401
        assert json.loads(resp.content) == {
            "code": "pw_session_expired",
            "detail": "Token expired or TOTP required for /api/v1/vaults",
        }

    @resp_mock.activate
    def test_passwork_403_in_search_maps_to_access_denied(self, user):
        """Passwork 403 on search → 403 pw_access_denied (previously — 200 with an empty list)."""
        grant_netbox_perm(user, "add_binding")
        mock_passwork_login()
        resp_mock.add(
            resp_mock.GET,
            f"{PASSWORK_URL}/api/v1/items/search",
            json=wrap_passwork_response({"errors": ["forbidden"]}),
            status=403,
        )

        with override_settings(PLUGINS_CONFIG=self.PLUGIN_CONFIG):
            self._login(user)
            resp = self._get(PickerSearchView, "/picker/search/", user, {"q": "router"})

        assert resp.status_code == 403
        assert json.loads(resp.content) == {
            "code": "pw_access_denied",
            "detail": "Access denied for /api/v1/items/search?query=router",
        }
