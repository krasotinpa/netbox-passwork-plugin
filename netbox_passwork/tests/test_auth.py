import ast
import inspect
import time
import warnings
from urllib.parse import parse_qs, urlsplit

import pytest
import requests
import responses as resp_mock
from urllib3.exceptions import InsecureRequestWarning

from netbox_passwork import passwork_client
from netbox_passwork.exceptions import (
    PassworkAccessDenied,
    PassworkBadResponse,
    PassworkSessionExpired,
    PassworkTimeout,
)
from netbox_passwork.passwork_client import PassworkAuthClient

BASE_URL = "https://passwork.test"


def make_client(**kwargs):
    return PassworkAuthClient(base_url=BASE_URL, verify_ssl=False, timeout=5, **kwargs)


def _session(
    access_token="acc",
    refresh_token="ref",
    csrf_token="csrf",
    access_expires=None,
    refresh_expires=None,
    requires_totp=False,
):
    now = int(time.time())
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "csrf_token": csrf_token,
        "access_token_expired_at": access_expires or now + 3600,
        "refresh_token_expired_at": refresh_expires or now + 86400,
        "requires_totp": requires_totp,
    }


def _b64(s: str) -> str:
    import base64
    import json

    return base64.b64encode(json.dumps({"csrfToken": s} if "csrf" in s else {}).encode()).decode()


def _wrap(data: dict) -> dict:
    """Wrap the response in base64 like Passwork."""
    import base64
    import json

    return {
        "format": "base64",
        "content": base64.b64encode(json.dumps(data).encode()).decode(),
    }


# ------------------------------------------------------------------
# Login
# ------------------------------------------------------------------


class TestLogin:
    @resp_mock.activate
    def test_successful_login_no_totp(self):
        resp_mock.add(resp_mock.POST, f"{BASE_URL}/api/v1/csrf-tokens/generate", json=_wrap({"csrfToken": "csrf1"}))
        resp_mock.add(
            resp_mock.POST,
            f"{BASE_URL}/api/v1/users/login",
            json=_wrap(
                {
                    "csrfToken": "csrf2",
                    "refreshToken": "ref1",
                    "accessTokenExpiredAt": int(time.time()) + 3600,
                    "refreshTokenExpiredAt": int(time.time()) + 86400,
                }
            ),
            headers={"Set-Cookie": "accessToken=acc1"},
        )
        resp_mock.add(resp_mock.GET, f"{BASE_URL}/api/v1/users/info", json=_wrap({"id": "1"}), status=200)

        data = make_client().login("user", "pass")
        assert data["requires_totp"] is False

    @resp_mock.activate
    def test_successful_login_with_totp_required(self):
        resp_mock.add(resp_mock.POST, f"{BASE_URL}/api/v1/csrf-tokens/generate", json=_wrap({"csrfToken": "csrf1"}))
        resp_mock.add(
            resp_mock.POST,
            f"{BASE_URL}/api/v1/users/login",
            json=_wrap(
                {
                    "csrfToken": "csrf2",
                    "refreshToken": "ref1",
                    "accessTokenExpiredAt": int(time.time()) + 3600,
                    "refreshTokenExpiredAt": int(time.time()) + 86400,
                }
            ),
        )
        resp_mock.add(
            resp_mock.GET, f"{BASE_URL}/api/v1/users/info", json=_wrap({"isTwoFactorAuthEnabled": True}), status=200
        )
        # Test request to check TOTP
        resp_mock.add(
            resp_mock.GET,
            f"{BASE_URL}/api/v1/items/search",
            json=_wrap({"errors": [{"code": "twoFactorAuthRequired"}]}),
            status=401,
        )

        data = make_client().login("user", "pass")
        assert data["requires_totp"] is True

    @resp_mock.activate
    def test_invalid_credentials_raises(self):
        resp_mock.add(resp_mock.POST, f"{BASE_URL}/api/v1/csrf-tokens/generate", json=_wrap({"csrfToken": "csrf1"}))
        resp_mock.add(
            resp_mock.POST,
            f"{BASE_URL}/api/v1/users/login",
            json=_wrap({"errors": [{"code": "invalidCredentials"}]}),
            status=401,
        )

        with pytest.raises(PassworkAccessDenied) as exc_info:
            make_client().login("user", "wrongpass")
        # the rejection context is known to the operation: login → invalid_credentials 401 (ADR-0001)
        assert exc_info.value.code == "invalid_credentials"
        assert exc_info.value.http_status == 401

    @resp_mock.activate
    def test_timeout_raises(self):
        resp_mock.add(resp_mock.POST, f"{BASE_URL}/api/v1/csrf-tokens/generate", body=requests.Timeout())

        with pytest.raises(PassworkTimeout):
            make_client().login("user", "pass")


# ------------------------------------------------------------------
# TOTP
# ------------------------------------------------------------------


class TestConfirmTotp:
    @resp_mock.activate
    def test_valid_totp(self):
        resp_mock.add(resp_mock.POST, f"{BASE_URL}/api/v1/users/2fa/totp/authorize", json=_wrap({}), status=200)

        data = make_client().confirm_totp("123456", _session(requires_totp=True))
        assert data["requires_totp"] is False

    @resp_mock.activate
    def test_invalid_totp_raises(self):
        resp_mock.add(
            resp_mock.POST,
            f"{BASE_URL}/api/v1/users/2fa/totp/authorize",
            json=_wrap({"errors": [{"code": "invalidCode"}]}),
            status=401,
        )

        with pytest.raises(PassworkAccessDenied) as exc_info:
            make_client().confirm_totp("000000", _session(requires_totp=True))
        assert exc_info.value.code == "invalid_totp"
        assert exc_info.value.http_status == 401


# ------------------------------------------------------------------
# Refresh
# ------------------------------------------------------------------


class TestRefreshIfNeeded:
    def test_no_refresh_needed(self):
        sess = _session(access_expires=int(time.time()) + 3600)
        result = make_client().refresh_if_needed(sess)
        assert result["access_token"] == "acc"

    def test_expired_refresh_token_raises(self):
        sess = _session(refresh_expires=int(time.time()) - 1)
        with pytest.raises(PassworkSessionExpired):
            make_client().refresh_if_needed(sess)

    @pytest.mark.parametrize("status", [401, 403])
    @resp_mock.activate
    def test_rejected_refresh_raises_session_expired(self, status):
        """401/403 from /sessions/refresh — refresh token rejected: session expired, not "success" with the old token."""
        resp_mock.add(resp_mock.POST, f"{BASE_URL}/api/v1/sessions/refresh", json=_wrap({"errors": []}), status=status)
        with pytest.raises(PassworkSessionExpired):
            make_client().refresh_if_needed(_session(access_expires=int(time.time()) + 30))

    @resp_mock.activate
    def test_refresh_access_token(self):
        resp_mock.add(
            resp_mock.POST,
            f"{BASE_URL}/api/v1/sessions/refresh",
            json=_wrap({"accessToken": "new_acc", "refreshToken": "new_ref"}),
            headers={"Set-Cookie": "accessToken=new_acc"},
        )

        sess = _session(access_expires=int(time.time()) + 30)
        result = make_client().refresh_if_needed(sess)
        # accessToken may arrive via a cookie or in the body
        assert result is not None

    @resp_mock.activate
    def test_refresh_margin_is_constructor_parameter(self):
        """The refresh margin comes from the constructor, not from Django settings."""
        resp_mock.add(
            resp_mock.POST,
            f"{BASE_URL}/api/v1/sessions/refresh",
            json=_wrap({}),
            headers={"Set-Cookie": "accessToken=new_acc"},
        )
        sess = _session(access_expires=int(time.time()) + 3600)

        make_client(refresh_margin=60).refresh_if_needed(dict(sess))
        assert len(resp_mock.calls) == 0, "with margin=60 a token with an hour of headroom is not refreshed"

        make_client(refresh_margin=7200).refresh_if_needed(dict(sess))
        assert len(resp_mock.calls) == 1, "with margin=7200 the same token is refreshed"

    @resp_mock.activate
    def test_refresh_rejected_raises(self):
        resp_mock.add(resp_mock.POST, f"{BASE_URL}/api/v1/sessions/refresh", json=_wrap({"errors": []}), status=401)

        sess = _session(access_expires=int(time.time()) + 30)
        with pytest.raises(PassworkSessionExpired):
            make_client().refresh_if_needed(sess)


# ------------------------------------------------------------------
# get_item
# ------------------------------------------------------------------


class TestGetItem:
    @resp_mock.activate
    def test_get_item_success(self):
        resp_mock.add(
            resp_mock.GET,
            f"{BASE_URL}/api/v1/items/pw123",
            json=_wrap(
                {
                    "id": "pw123",
                    "name": "Test",
                    "login": "admin",
                    "passwordEncrypted": "c2VjcmV0",  # base64('secret')
                    "customs": [],
                    "description": None,
                    "url": None,
                }
            ),
        )

        result = make_client().get_item("pw123", _session())
        assert result["name"] == "Test"
        assert result["password"] == "secret"

    @resp_mock.activate
    def test_get_item_access_denied(self):
        resp_mock.add(resp_mock.GET, f"{BASE_URL}/api/v1/items/pw123", json=_wrap({"errors": []}), status=403)

        with pytest.raises(PassworkAccessDenied):
            make_client().get_item("pw123", _session())

    @resp_mock.activate
    def test_get_item_not_found_returns_empty(self):
        resp_mock.add(resp_mock.GET, f"{BASE_URL}/api/v1/items/pw_gone", json=_wrap({}), status=404)

        result = make_client().get_item("pw_gone", _session())
        assert result == {}

    @resp_mock.activate
    def test_get_item_timeout(self):
        resp_mock.add(resp_mock.GET, f"{BASE_URL}/api/v1/items/pw123", body=requests.Timeout())

        with pytest.raises(PassworkTimeout):
            make_client().get_item("pw123", _session())


# ------------------------------------------------------------------
# list_vaults
# ------------------------------------------------------------------


class TestListVaults:
    VAULTS_URL = f"{BASE_URL}/api/v1/vaults"

    @resp_mock.activate
    def test_success_returns_items(self):
        resp_mock.add(resp_mock.GET, self.VAULTS_URL, json=_wrap({"items": [{"id": "v1", "name": "Vault1"}]}))

        result = make_client().list_vaults(_session(access_token="acc", csrf_token="csrf"))

        assert result == [{"id": "v1", "name": "Vault1"}]
        sent = resp_mock.calls[0].request.headers
        assert sent["Authorization"] == "Bearer acc"
        assert sent["X-CSRF-Token"] == "csrf"
        assert sent["X-Browser-Mode"] == "1"

    @resp_mock.activate
    def test_401_raises_session_expired(self):
        resp_mock.add(resp_mock.GET, self.VAULTS_URL, json=_wrap({"errors": []}), status=401)
        with pytest.raises(PassworkSessionExpired):
            make_client().list_vaults(_session())

    @resp_mock.activate
    def test_403_raises_access_denied(self):
        resp_mock.add(resp_mock.GET, self.VAULTS_URL, json=_wrap({"errors": []}), status=403)
        with pytest.raises(PassworkAccessDenied):
            make_client().list_vaults(_session())

    @resp_mock.activate
    def test_timeout_raises(self):
        resp_mock.add(resp_mock.GET, self.VAULTS_URL, body=requests.Timeout())
        with pytest.raises(PassworkTimeout):
            make_client().list_vaults(_session())

    @resp_mock.activate
    def test_non_json_raises_bad_response(self):
        resp_mock.add(resp_mock.GET, self.VAULTS_URL, body="<html>502 Bad Gateway</html>", status=502)
        with pytest.raises(PassworkBadResponse):
            make_client().list_vaults(_session())


# ------------------------------------------------------------------
# search_items
# ------------------------------------------------------------------


class TestSearchItems:
    SEARCH_URL = f"{BASE_URL}/api/v1/items/search"

    @resp_mock.activate
    def test_success_returns_items(self):
        resp_mock.add(resp_mock.GET, self.SEARCH_URL, json=_wrap({"items": [{"id": "pw1", "name": "Router"}]}))

        result = make_client().search_items("router", _session(access_token="acc", csrf_token="csrf"))

        assert result == [{"id": "pw1", "name": "Router"}]
        request = resp_mock.calls[0].request
        assert parse_qs(urlsplit(request.url).query) == {"query": ["router"]}
        assert request.headers["Authorization"] == "Bearer acc"
        assert request.headers["X-CSRF-Token"] == "csrf"

    @resp_mock.activate
    def test_search_query_is_url_encoded(self):
        """H1: special characters in the query do not inject parameters into the Passwork API."""
        resp_mock.add(resp_mock.GET, self.SEARCH_URL, json=_wrap({"items": []}))

        make_client().search_items("test&perPage=9999", _session())

        url = resp_mock.calls[0].request.url
        # Without encoding the URL would be: .../items/search?query=test&perPage=9999
        assert "&perPage=9999" not in url, "query not encoded — parameter injection possible"
        assert "%26" in url, "& must be encoded as %26 in the Passwork API path"
        assert parse_qs(urlsplit(url).query) == {"query": ["test&perPage=9999"]}

    @resp_mock.activate
    def test_401_raises_session_expired(self):
        resp_mock.add(resp_mock.GET, self.SEARCH_URL, json=_wrap({"errors": []}), status=401)
        with pytest.raises(PassworkSessionExpired):
            make_client().search_items("x", _session())

    @resp_mock.activate
    def test_403_raises_access_denied(self):
        resp_mock.add(resp_mock.GET, self.SEARCH_URL, json=_wrap({"errors": []}), status=403)
        with pytest.raises(PassworkAccessDenied):
            make_client().search_items("x", _session())

    @resp_mock.activate
    def test_timeout_raises(self):
        resp_mock.add(resp_mock.GET, self.SEARCH_URL, body=requests.Timeout())
        with pytest.raises(PassworkTimeout):
            make_client().search_items("x", _session())

    @resp_mock.activate
    def test_non_json_raises_bad_response(self):
        resp_mock.add(resp_mock.GET, self.SEARCH_URL, body="<html>502 Bad Gateway</html>", status=502)
        with pytest.raises(PassworkBadResponse):
            make_client().search_items("x", _session())


# ------------------------------------------------------------------
# Client — pure HTTP implementation without Django
# ------------------------------------------------------------------


def _ignores_insecure_request_warning() -> bool:
    return any(
        action == "ignore" and issubclass(InsecureRequestWarning, category)
        for action, _, category, *_ in warnings.filters
    )


class TestClientIsPureHttp:
    def _module_tree(self):
        return ast.parse(inspect.getsource(passwork_client))

    def test_no_django_and_no_local_imports(self):
        """Everything the client needs comes through the constructor; imports only at module level (L2)."""
        tree = self._module_tree()
        top_level = {id(node) for node in tree.body}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [alias.name for alias in node.names] + [getattr(node, "module", None) or ""]
                assert not any(n.split(".")[0] == "django" for n in names), f"client imports Django: {names}"
                assert id(node) in top_level, f"local import inside a function: {ast.dump(node)}"

    def test_disable_warnings_not_called_at_import(self):
        """L4: urllib3.disable_warnings() is not called at module level."""
        for node in self._module_tree().body:
            call = getattr(node, "value", None)
            assert not (isinstance(call, ast.Call) and getattr(call.func, "attr", None) == "disable_warnings"), (
                "urllib3.disable_warnings() is called at module import"
            )

    def test_disable_warnings_only_when_verify_ssl_false(self):
        with warnings.catch_warnings():
            warnings.resetwarnings()
            PassworkAuthClient(base_url=BASE_URL, verify_ssl=True)
            assert not _ignores_insecure_request_warning(), "warnings are suppressed with verify_ssl=True"
            PassworkAuthClient(base_url=BASE_URL, verify_ssl=False)
            assert _ignores_insecure_request_warning(), "warnings are not suppressed with verify_ssl=False"


# ------------------------------------------------------------------
# _decode
# ------------------------------------------------------------------


class _Response:
    """Minimal stub of requests.Response for _decode: status_code + json()."""

    def __init__(self, status_code=200, json_data=None, json_error=None):
        self.status_code = status_code
        self._json_data = json_data
        self._json_error = json_error

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        return self._json_data


class TestDecode:
    """Tests for _decode: resilience to a non-JSON response."""

    def test_non_json_response_raises_passwork_bad_response(self):
        """An HTML error page from the proxy/Passwork must not cause an unhandled exception."""
        from netbox_passwork.exceptions import PassworkBadResponse
        from netbox_passwork.passwork_client import _decode

        response = _Response(status_code=502, json_error=ValueError("No JSON object could be decoded"))

        with pytest.raises(PassworkBadResponse) as exc_info:
            _decode(response)

        assert "502" in str(exc_info.value)

    def test_valid_json_passes_through(self):
        """Valid JSON is returned unchanged."""
        from netbox_passwork.passwork_client import _decode

        response = _Response(json_data={"status": "ok"})

        result = _decode(response)
        assert result == {"status": "ok"}
