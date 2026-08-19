"""
Tests for the base view of views that talk to Passwork: the order of checks in dispatch,
permission_required = None, requires_passwork_session = False, translating PassworkError into
{"code", "detail"}. The gateway is injected through the ``as_view(gateway_factory=...)`` seam.
"""

import json

import pytest
from django.contrib.auth.models import AnonymousUser
from django.http import JsonResponse
from django.test import RequestFactory
from django.views import View

from netbox_passwork.exceptions import (
    PassworkAccessDenied,
    PassworkBadResponse,
    PassworkError,
    PassworkSessionExpired,
    PassworkTimeout,
)
from netbox_passwork.gateway import build_gateway
from netbox_passwork.permissions import RequireNetboxPermMixin
from netbox_passwork.tests.conftest import FakeGateway, grant_netbox_perm
from netbox_passwork.views import ApiError, PassworkView


class _ProbeView(PassworkView):
    """GET → 200 {"ok": true}; get_item via self.gateway; exception — if set."""

    permission_required = "view_secrets"
    raise_in_method = None

    def get(self, request):
        if self.raise_in_method is not None:
            raise self.raise_in_method
        return JsonResponse({"ok": True, "item": self.gateway.get_item("pw1")})


class _NoPermView(PassworkView):
    permission_required = None

    def get(self, request):
        return JsonResponse({"ok": True})


class _NoSessionView(PassworkView):
    permission_required = None
    requires_passwork_session = False

    def post(self, request):
        return JsonResponse({"requires_totp": self.gateway.login("u", "p")})


class _MixinNoPermView(RequireNetboxPermMixin, View):
    permission_required = None

    def get(self, request):
        return JsonResponse({"ok": True})


def _request(user, method="get"):
    request = getattr(RequestFactory(), method)("/")
    request.user = user
    request.session = {}
    return request


def _body(response) -> dict:
    return json.loads(response.content)


def _factory(fake):
    return lambda request: fake


def _never_called(request):
    raise AssertionError("gateway_factory must not be called before the NetBox permission check")


@pytest.mark.django_db
class TestDispatchOrder:
    """401 NetBox → 403 permissions → 401 Passwork session → method."""

    def test_anonymous_401_before_gateway(self):
        response = _ProbeView.as_view(gateway_factory=_never_called)(_request(AnonymousUser()))
        assert response.status_code == 401
        assert _body(response) == {"detail": "Authentication required", "code": "not_authenticated"}

    def test_no_permission_403_before_gateway(self, user):
        response = _ProbeView.as_view(gateway_factory=_never_called)(_request(user))
        assert response.status_code == 403
        assert _body(response) == {"detail": "Permission denied", "code": "netbox_permission_denied"}

    def test_no_passwork_session_401_before_method(self, user):
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(
            require_session=PassworkError("Passwork session not found", code="pw_not_authenticated", http_status=401)
        )

        response = _ProbeView.as_view(gateway_factory=_factory(fake))(_request(user))

        assert response.status_code == 401
        assert _body(response) == {"code": "pw_not_authenticated", "detail": "Passwork session not found"}
        assert fake.calls == [("require_session",)], "the view method was not called"

    def test_expired_passwork_session_401_before_method(self, user):
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(require_session=PassworkSessionExpired())

        response = _ProbeView.as_view(gateway_factory=_factory(fake))(_request(user))

        assert response.status_code == 401
        assert _body(response)["code"] == "pw_session_expired"
        assert fake.calls == [("require_session",)]

    def test_all_checks_pass_then_method_runs_with_gateway(self, user):
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(get_item={"name": "Router"})

        response = _ProbeView.as_view(gateway_factory=_factory(fake))(_request(user))

        assert response.status_code == 200
        assert _body(response) == {"ok": True, "item": {"name": "Router"}}
        assert fake.calls == [("require_session",), ("get_item", "pw1")]

    def test_factory_receives_request(self, user):
        grant_netbox_perm(user, "view_secrets")
        seen = []

        def factory(request):
            seen.append(request)
            return FakeGateway()

        request = _request(user)
        _ProbeView.as_view(gateway_factory=factory)(request)
        assert seen == [request]

    def test_unsupported_method_405_before_gateway(self, user):
        """Unsupported method → 405 (like Django), the gateway is not built and no Passwork session is needed."""
        grant_netbox_perm(user, "view_secrets")
        response = _ProbeView.as_view(gateway_factory=_never_called)(_request(user, "post"))
        assert response.status_code == 405
        assert response["Allow"] and "GET" in response["Allow"]

    def test_options_does_not_require_passwork_session(self, user):
        """OPTIONS — metadata (Allow), the Passwork session is not checked."""
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(require_session=PassworkSessionExpired())
        response = _ProbeView.as_view(gateway_factory=_factory(fake))(_request(user, "options"))
        assert response.status_code == 200
        assert "GET" in response["Allow"]
        assert fake.calls == []


@pytest.mark.django_db
class TestPermissionRequiredNone:
    """permission_required = None — NetBox authentication only."""

    def test_anonymous_401(self):
        response = _NoPermView.as_view(gateway_factory=_never_called)(_request(AnonymousUser()))
        assert response.status_code == 401
        assert _body(response)["code"] == "not_authenticated"

    def test_authenticated_without_any_permission_passes(self, user):
        response = _NoPermView.as_view(gateway_factory=_factory(FakeGateway()))(_request(user))
        assert response.status_code == 200
        assert _body(response) == {"ok": True}

    def test_mixin_alone_supports_none(self, user):
        assert _MixinNoPermView.as_view()(_request(AnonymousUser())).status_code == 401
        assert _MixinNoPermView.as_view()(_request(user)).status_code == 200


@pytest.mark.django_db
class TestRequiresPassworkSessionFalse:
    def test_session_not_touched_and_method_runs(self, user):
        fake = FakeGateway(login=True)

        response = _NoSessionView.as_view(gateway_factory=_factory(fake))(_request(user, "post"))

        assert response.status_code == 200
        assert _body(response) == {"requires_totp": True}
        assert fake.calls == [("login", "u", "p")], "require_session was not called"

    def test_gateway_still_built(self, user):
        seen = []

        def factory(request):
            seen.append(request)
            return FakeGateway()

        _NoSessionView.as_view(gateway_factory=factory)(_request(user, "post"))
        assert len(seen) == 1

    def test_default_is_true(self):
        assert PassworkView.requires_passwork_session is True


@pytest.mark.django_db
class TestPassworkErrorToJson:
    """Every PassworkError from the view method → {"code", "detail"} with the status from the exception."""

    @pytest.mark.parametrize(
        ("exc", "status", "code"),
        [
            (PassworkSessionExpired(), 401, "pw_session_expired"),
            (PassworkAccessDenied(), 403, "pw_access_denied"),
            (PassworkTimeout(), 504, "pw_timeout"),
            (PassworkBadResponse(), 502, "pw_bad_response"),
            (PassworkError(), 502, "pw_error"),
            (
                PassworkAccessDenied("Invalid credentials", code="invalid_credentials", http_status=401),
                401,
                "invalid_credentials",
            ),
            (PassworkAccessDenied("Invalid TOTP code", code="invalid_totp", http_status=401), 401, "invalid_totp"),
            (
                PassworkError("Passwork session not found", code="pw_not_authenticated", http_status=401),
                401,
                "pw_not_authenticated",
            ),
        ],
        ids=lambda v: v.code if isinstance(v, PassworkError) else "",
    )
    def test_error_from_method(self, user, exc, status, code):
        grant_netbox_perm(user, "view_secrets")
        view = _ProbeView.as_view(gateway_factory=_factory(FakeGateway()), raise_in_method=exc)

        response = view(_request(user))

        assert response.status_code == status
        body = _body(response)
        assert set(body) == {"code", "detail"}
        assert body["code"] == code
        assert body["detail"] == exc.detail

    def test_error_from_gateway_operation(self, user):
        grant_netbox_perm(user, "view_secrets")
        fake = FakeGateway(get_item=PassworkAccessDenied("Access denied for /api/v1/items/pw1"))

        response = _ProbeView.as_view(gateway_factory=_factory(fake))(_request(user))

        assert response.status_code == 403
        assert _body(response) == {"code": "pw_access_denied", "detail": "Access denied for /api/v1/items/pw1"}

    def test_non_passwork_exception_propagates(self, user):
        grant_netbox_perm(user, "view_secrets")
        view = _ProbeView.as_view(gateway_factory=_factory(FakeGateway()), raise_in_method=RuntimeError("bug"))
        with pytest.raises(RuntimeError):
            view(_request(user))

    def test_api_error_from_method(self, user):
        """ApiError (a plugin API-level rejection: parameters/binding) → the same {"code","detail"} with its own status."""
        grant_netbox_perm(user, "view_secrets")
        view = _ProbeView.as_view(
            gateway_factory=_factory(FakeGateway()),
            raise_in_method=ApiError("Binding not found", code="binding_not_found", http_status=404),
        )
        response = view(_request(user))
        assert response.status_code == 404
        assert _body(response) == {"code": "binding_not_found", "detail": "Binding not found"}


class TestSeam:
    def test_default_gateway_factory_is_build_gateway(self):
        assert PassworkView.gateway_factory is build_gateway

    def test_view_is_a_netbox_perm_view(self):
        assert issubclass(PassworkView, RequireNetboxPermMixin)
