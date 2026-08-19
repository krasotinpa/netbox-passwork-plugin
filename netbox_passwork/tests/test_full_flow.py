"""
Phase 7.1: Full flow — login → tab → lazy load → reveal → AuditLog;
end-to-end scenarios on the real gateway (``build_gateway`` + ``responses``), including the
1.3.0 release scenario and compatibility with a Passwork session record created before the upgrade.
"""

import base64
import json
import time

import pytest
import responses as resp_mock
from cryptography.fernet import Fernet
from django.test import RequestFactory, override_settings
from responses import matchers

from netbox_passwork.models import PassworkAuditLog, PassworkBinding
from netbox_passwork.tests.conftest import (
    PASSWORK_URL,
    FakeGateway,
    grant_netbox_perm,
    mock_passwork_login,
    no_passwork_session,
    wrap_passwork_response,
)
from netbox_passwork.views import (
    BindingsCreateView,
    PassworkLoginView,
    PassworkTotpView,
    PickerFoldersView,
    PickerSearchView,
    SecretCopyView,
    SecretDetailView,
    SecretsListView,
)

ITEM = {
    "name": "Test Secret",
    "login": "admin",
    "password": "supersecret",
    "custom_fields": [],
    "description": "",
    "url": "",
}


@pytest.mark.django_db
class TestFullFlow:
    """ "Tab" scenario: list of bindings → lazy-load details → reveal → audit; Passwork — FakeGateway."""

    def setup_method(self):
        self.factory = RequestFactory()
        self.list_view = SecretsListView.as_view()

    def _detail_view(self, fake=None):
        return SecretDetailView.as_view(gateway_factory=lambda request: fake or FakeGateway(get_item=ITEM))

    def _make_request(self, method, path, user, params=None):
        request = getattr(self.factory, method)(path, params or {})
        request.user = user
        request.session = {}
        return request

    def _get_detail(self, user, pw_id="abc123", reveal=False):
        params = {"object_type": "device", "object_id": "1"}
        if reveal:
            params["reveal"] = "true"
        return self._make_request("get", f"/secrets/{pw_id}/detail/", user, params)

    def test_secrets_list_returns_bindings(self, user, binding):
        """GET /secrets/ returns the list of bindings for the object."""
        grant_netbox_perm(user, "view_secrets")
        request = self._make_request(
            "get",
            "/secrets/",
            user,
            params={"object_type": "device", "object_id": "1"},
        )
        resp = self.list_view(request)
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert len(data) == 1
        assert data[0]["pw_id"] == "abc123"
        assert "binding_id" in data[0]

    def test_lazy_load_meta_without_auth_returns_401(self, user, binding):
        """detail/ without a Passwork session → 401 pw_not_authenticated."""
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(require_session=no_passwork_session())
        resp = self._detail_view(fake)(self._get_detail(user), pw_id="abc123")
        assert resp.status_code == 401
        assert json.loads(resp.content)["code"] == "pw_not_authenticated"

    def test_lazy_load_meta_returns_name_login(self, user, binding):
        """detail/ without reveal → name and login, no password."""
        grant_netbox_perm(user, "view_secrets")
        resp = self._detail_view()(self._get_detail(user), pw_id="abc123")
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data["name"] == "Test Secret"
        assert data["login"] == "admin"
        assert "password" not in data

    def test_reveal_creates_audit_log(self, user, binding):
        """detail/?reveal=true → password + an AuditLog entry."""
        grant_netbox_perm(user, "view_secrets")
        grant_netbox_perm(user, "reveal_secret")
        resp = self._detail_view()(self._get_detail(user, reveal=True), pw_id="abc123")
        assert resp.status_code == 200
        assert json.loads(resp.content)["password"] == "supersecret"

        log = PassworkAuditLog.objects.filter(passwork_item_id="abc123", action="reveal", netbox_user=user).first()
        assert log is not None
        assert log.object_type == "device"
        assert log.object_id == 1

    def test_reveal_without_permission_returns_403(self, user, binding):
        """reveal=true without reveal_secret permission → 403, the gateway is not touched."""
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(get_item=ITEM)
        resp = self._detail_view(fake)(self._get_detail(user, reveal=True), pw_id="abc123")
        assert resp.status_code == 403
        assert fake.calls == []

    def test_arbitrary_pw_id_not_in_binding_returns_404(self, user, binding):
        """detail/ with a pw_id not from a binding → 404 (protection against proxy abuse), get_item is not called."""
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(get_item=ITEM)
        resp = self._detail_view(fake)(self._get_detail(user, pw_id="ARBITRARY_ID"), pw_id="ARBITRARY_ID")
        assert resp.status_code == 404
        assert json.loads(resp.content)["code"] == "binding_not_found"
        assert fake.calls == [("require_session",)]


# ---------------------------------------------------------------------------
# End-to-end scenario (#14/#15): login via the gateway → detail/reveal and copy via the gateway, real build_gateway
# ---------------------------------------------------------------------------


def _mock_passwork_item(pw_id: str, name: str, password: str):
    resp_mock.add(
        resp_mock.GET,
        f"{PASSWORK_URL}/api/v1/items/{pw_id}",
        json=wrap_passwork_response(
            {
                "name": name,
                "login": "admin",
                "passwordEncrypted": base64.b64encode(password.encode()).decode(),
                "customs": [],
                "url": "",
            }
        ),
    )


@pytest.mark.django_db
class TestLoginThenSecretsViaGateway:
    """
    One real gateway (``build_gateway``, Passwork — ``responses``) for the whole scenario:
    Login/Totp store the Passwork session in the Django session, Detail/Copy read it from there,
    reveal and copy write to the audit log.
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

    def _post_json(self, path, user, body):
        request = self.factory.post(path, data=json.dumps(body), content_type="application/json")
        request.user = user
        request.session = self.session
        return request

    def _get_detail(self, user, pw_id, reveal=False):
        params = {"object_type": "device", "object_id": "1"}
        if reveal:
            params["reveal"] = "true"
        request = self.factory.get(f"/secrets/{pw_id}/detail/", params)
        request.user = user
        request.session = self.session
        return SecretDetailView.as_view()(request, pw_id=pw_id)

    def _post_copy(self, user, pw_id):
        request = self.factory.post(f"/secrets/{pw_id}/copy/?object_type=device&object_id=1")
        request.user = user
        request.session = self.session
        return SecretCopyView.as_view()(request, pw_id=pw_id)

    @resp_mock.activate
    def test_login_then_detail_reads_secret(self, user, binding):
        grant_netbox_perm(user, "view_secrets")
        grant_netbox_perm(user, "reveal_secret")
        mock_passwork_login()
        _mock_passwork_item("abc123", "Core Router", "s3cret")

        with override_settings(PLUGINS_CONFIG=self.PLUGIN_CONFIG):
            resp = PassworkLoginView.as_view()(
                self._post_json("/auth/login/", user, {"username": "u", "password": "p"})
            )
            assert resp.status_code == 200
            assert json.loads(resp.content) == {"status": "ok", "requires_totp": False}
            assert "pw_session" in self.session, "the gateway wrote the Passwork session into the Django session"

            resp = self._get_detail(user, "abc123", reveal=True)
            assert resp.status_code == 200, resp.content
            data = json.loads(resp.content)
            assert data["name"] == "Core Router"
            assert data["password"] == "s3cret"
            item_call = resp_mock.calls[-1].request
            assert item_call.headers["Authorization"] == "Bearer acc1", "detail read the tokens saved by login"
            assert item_call.headers["X-CSRF-Token"] == "csrf2"
            calls_before_copy = len(resp_mock.calls)

            resp = self._post_copy(user, "abc123")

        assert resp.status_code == 200, resp.content
        assert json.loads(resp.content) == {"status": "ok"}
        assert len(resp_mock.calls) == calls_before_copy, "copy does not reach out to Passwork"
        actions = list(PassworkAuditLog.objects.filter(passwork_item_id="abc123").values_list("action", flat=True))
        assert sorted(actions) == ["copy", "reveal"]

    @resp_mock.activate
    def test_detail_passwork_403_maps_to_pw_access_denied(self, user, binding):
        """Real failure chain: Passwork 403 → PassworkAccessDenied in the client → gateway → PassworkView → 403 {"code","detail"}."""
        grant_netbox_perm(user, "view_secrets")
        mock_passwork_login()
        resp_mock.add(
            resp_mock.GET,
            f"{PASSWORK_URL}/api/v1/items/abc123",
            json=wrap_passwork_response({"errors": ["forbidden"]}),
            status=403,
        )

        with override_settings(PLUGINS_CONFIG=self.PLUGIN_CONFIG):
            PassworkLoginView.as_view()(self._post_json("/auth/login/", user, {"username": "u", "password": "p"}))
            resp = self._get_detail(user, "abc123")

        assert resp.status_code == 403
        assert json.loads(resp.content) == {
            "code": "pw_access_denied",
            "detail": "Access denied for /api/v1/items/abc123",
        }
        assert not PassworkAuditLog.objects.filter(passwork_item_id="abc123").exists()

    @resp_mock.activate
    def test_login_totp_then_detail_reads_secret(self, user, binding):
        grant_netbox_perm(user, "view_secrets")
        mock_passwork_login(requires_totp=True)
        resp_mock.add(
            resp_mock.POST,
            f"{PASSWORK_URL}/api/v1/users/2fa/totp/authorize",
            json=wrap_passwork_response({"status": "ok"}),
        )
        _mock_passwork_item("abc123", "Core Router", "s3cret")

        with override_settings(PLUGINS_CONFIG=self.PLUGIN_CONFIG):
            resp = PassworkLoginView.as_view()(
                self._post_json("/auth/login/", user, {"username": "u", "password": "p"})
            )
            assert json.loads(resp.content) == {"status": "totp_required", "requires_totp": True}

            resp = PassworkTotpView.as_view()(self._post_json("/auth/totp/", user, {"code": "123456"}))
            assert resp.status_code == 200, resp.content
            assert json.loads(resp.content) == {"status": "ok"}

            resp = self._get_detail(user, "abc123")

        assert resp.status_code == 200, resp.content
        assert json.loads(resp.content)["name"] == "Core Router"
        totp_call = next(c.request for c in resp_mock.calls if c.request.url.endswith("/2fa/totp/authorize"))
        assert totp_call.headers["Authorization"] == "Bearer acc1"
        assert json.loads(totp_call.body) == {"code": "123456"}


# ---------------------------------------------------------------------------
# 1.3.0 release scenario (#17): login → TOTP → list → reveal → copy → picker → binding —
# one real gateway for everything; plus a Passwork session written by version ≤ 1.2.x keeps working
# ---------------------------------------------------------------------------

_LEGACY_ENCRYPTED_FIELDS = ("access_token", "refresh_token", "csrf_token")


def _pre_1_3_record(session_data: dict, key: bytes) -> dict:
    """A ``pw_session`` record in the format of versions ≤ 1.2.x (``PassworkAuthClient.encrypt_session``)."""
    f = Fernet(key)
    return {
        k: f.encrypt(str(v).encode()).decode() if k in _LEGACY_ENCRYPTED_FIELDS else v for k, v in session_data.items()
    }


@pytest.mark.django_db
class TestReleaseScenarioViaGateway:
    KEY = Fernet.generate_key()
    PLUGIN_CONFIG = {
        "netbox_passwork": {"PASSWORK_URL": PASSWORK_URL, "PASSWORK_VERIFY_SSL": False, "SESSION_ENCRYPT_KEY": KEY}
    }

    def setup_method(self):
        self.factory = RequestFactory()
        self.session = {}  # a single "Django session" for the whole scenario

    def _call(self, view_class, method, path, user, params=None, body=None, **kwargs):
        if body is not None:
            request = getattr(self.factory, method)(path, data=json.dumps(body), content_type="application/json")
        else:
            request = getattr(self.factory, method)(path, params or {})
        request.user = user
        request.session = self.session
        return view_class.as_view()(request, **kwargs)

    @resp_mock.activate
    def test_full_release_scenario(self, user, binding):
        for action in ("view_secrets", "reveal_secret", "add_binding"):
            grant_netbox_perm(user, action)
        mock_passwork_login(requires_totp=True)
        resp_mock.add(
            resp_mock.POST,
            f"{PASSWORK_URL}/api/v1/users/2fa/totp/authorize",
            json=wrap_passwork_response({"status": "ok"}),
        )
        _mock_passwork_item("abc123", "Core Router", "s3cret")
        resp_mock.add(
            resp_mock.GET, f"{PASSWORK_URL}/api/v1/vaults", json=wrap_passwork_response({"items": [{"id": "v1"}]})
        )
        # The test login search (query=_totp_check_) is already mocked in mock_passwork_login; this response is for the picker only
        resp_mock.add(
            resp_mock.GET,
            f"{PASSWORK_URL}/api/v1/items/search",
            match=[matchers.query_param_matcher({"query": "edge"})],
            json=wrap_passwork_response({"items": [{"id": "pw_new_001", "name": "Edge Router"}]}),
        )
        secrets_q = {"object_type": "device", "object_id": "1"}

        with override_settings(PLUGINS_CONFIG=self.PLUGIN_CONFIG):
            resp = self._call(PassworkLoginView, "post", "/auth/login/", user, body={"username": "u", "password": "p"})
            assert json.loads(resp.content) == {"status": "totp_required", "requires_totp": True}
            resp = self._call(PassworkTotpView, "post", "/auth/totp/", user, body={"code": "123456"})
            assert json.loads(resp.content) == {"status": "ok"}, resp.content

            resp = self._call(SecretsListView, "get", "/secrets/", user, secrets_q)
            assert json.loads(resp.content) == [{"pw_id": "abc123", "binding_id": binding.pk}]

            resp = self._call(
                SecretDetailView,
                "get",
                "/secrets/abc123/detail/",
                user,
                {**secrets_q, "reveal": "true"},
                pw_id="abc123",
            )
            assert resp.status_code == 200, resp.content
            assert json.loads(resp.content)["password"] == "s3cret"

            resp = self._call(
                SecretCopyView, "post", "/secrets/abc123/copy/?object_type=device&object_id=1", user, pw_id="abc123"
            )
            assert json.loads(resp.content) == {"status": "ok"}

            resp = self._call(PickerFoldersView, "get", "/picker/folders/", user)
            assert json.loads(resp.content) == [{"id": "v1"}]
            resp = self._call(PickerSearchView, "get", "/picker/search/", user, {"q": "edge"})
            assert json.loads(resp.content) == [{"id": "pw_new_001", "name": "Edge Router"}]

            resp = self._call(
                BindingsCreateView,
                "post",
                "/bindings/",
                user,
                body={"object_type": "device", "object_id": 42, "passwork_item_id": "pw_new_001"},
            )
            assert resp.status_code == 201, resp.content

        assert PassworkBinding.objects.filter(
            object_type="device", object_id=42, passwork_item_id="pw_new_001"
        ).exists()
        actions = sorted(PassworkAuditLog.objects.filter(passwork_item_id="abc123").values_list("action", flat=True))
        assert actions == ["copy", "reveal"]
        assert "pw_session" in self.session
        for call in resp_mock.calls[
            4:
        ]:  # after login/TOTP all requests carry the tokens of the stored Passwork session
            assert call.request.headers["Authorization"] == "Bearer acc1"

    @resp_mock.activate
    def test_session_record_written_before_1_3_keeps_working(self, user, binding):
        """A Passwork session written by version ≤ 1.2.x is read by the gateway without a repeated login."""
        grant_netbox_perm(user, "view_secrets")
        _mock_passwork_item("abc123", "Core Router", "s3cret")
        now = int(time.time())
        self.session["pw_session"] = _pre_1_3_record(
            {
                "access_token": "legacy_acc",
                "refresh_token": "legacy_ref",
                "csrf_token": "legacy_csrf",
                "access_token_expired_at": now + 3600,
                "refresh_token_expired_at": now + 86400,
                "requires_totp": False,
            },
            self.KEY,
        )

        with override_settings(PLUGINS_CONFIG=self.PLUGIN_CONFIG):
            resp = self._call(
                SecretDetailView,
                "get",
                "/secrets/abc123/detail/",
                user,
                {"object_type": "device", "object_id": "1"},
                pw_id="abc123",
            )

        assert resp.status_code == 200, resp.content
        assert json.loads(resp.content)["name"] == "Core Router"
        item_call = resp_mock.calls[0].request
        assert item_call.headers["Authorization"] == "Bearer legacy_acc"
        assert item_call.headers["X-CSRF-Token"] == "legacy_csrf"
