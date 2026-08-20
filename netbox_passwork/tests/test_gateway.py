"""
Tests for the Passwork gateway: a dict acting as storage, a client on `responses` — without
a Django session and `request`. Only building the gateway per request (`build_gateway`)
is verified on a `RequestFactory` request with a dict instead of a session.
"""

import base64
import contextlib
import inspect
import json
import logging
import time

import pytest
import requests
import responses as resp_mock
from cryptography.fernet import Fernet
from django.test import RequestFactory, override_settings

from netbox_passwork.exceptions import (
    PassworkAccessDenied,
    PassworkBadResponse,
    PassworkError,
    PassworkSessionExpired,
    PassworkTimeout,
)
from netbox_passwork.gateway import PassworkGateway, build_gateway
from netbox_passwork.passwork_client import PassworkAuthClient
from netbox_passwork.tests.conftest import FakeGateway

BASE_URL = "https://passwork.test"
ENCRYPT_KEY = Fernet.generate_key()
FERNET = Fernet(ENCRYPT_KEY)

# The key and the shape of the Passwork session record in storage before 1.3.0 are pinned literally,
# to catch any discrepancy (existing users must not be logged out).
STORAGE_KEY = "pw_session"
ENCRYPTED_FIELDS = ("access_token", "refresh_token", "csrf_token")
PLAIN_FIELDS = ("access_token_expired_at", "refresh_token_expired_at", "requires_totp")

CSRF_URL = f"{BASE_URL}/api/v1/csrf-tokens/generate"
LOGIN_URL = f"{BASE_URL}/api/v1/users/login"
INFO_URL = f"{BASE_URL}/api/v1/users/info"
TOTP_URL = f"{BASE_URL}/api/v1/users/2fa/totp/authorize"
REFRESH_URL = f"{BASE_URL}/api/v1/sessions/refresh"
ITEM_URL = f"{BASE_URL}/api/v1/items/pw123"
VAULTS_URL = f"{BASE_URL}/api/v1/vaults"
SEARCH_URL = f"{BASE_URL}/api/v1/items/search"
FOLDERS_URL = f"{BASE_URL}/api/v1/folders"
ITEMS_URL = f"{BASE_URL}/api/v1/items"


def _wrap(data: dict) -> dict:
    """Wrap the response in base64 like Passwork."""
    return {"format": "base64", "content": base64.b64encode(json.dumps(data).encode()).decode()}


def _session(access_expires=None, refresh_expires=None, requires_totp=False, **overrides) -> dict:
    now = int(time.time())
    return {
        "access_token": "acc",
        "refresh_token": "ref",
        "csrf_token": "csrf",
        "access_token_expired_at": access_expires or now + 3600,
        "refresh_token_expired_at": refresh_expires or now + 86400,
        "requires_totp": requires_totp,
        **overrides,
    }


_LEGACY_ENCRYPTED_FIELDS = ("access_token", "refresh_token", "csrf_token")


def _legacy_record(session_data: dict, key: bytes = ENCRYPT_KEY) -> dict:
    """A Passwork session record in the format of versions ≤ 1.2.x (PassworkAuthClient.encrypt_session): three fields — Fernet tokens."""
    f = Fernet(key)
    return {
        k: f.encrypt(str(v).encode()).decode() if k in _LEGACY_ENCRYPTED_FIELDS else v for k, v in session_data.items()
    }


def _decrypted(record: dict, key: bytes = ENCRYPT_KEY) -> dict:
    """Decrypt the record the way versions ≤ 1.2.x did (PassworkAuthClient.decrypt_session)."""
    f = Fernet(key)
    return {k: f.decrypt(v.encode()).decode() if k in _LEGACY_ENCRYPTED_FIELDS else v for k, v in record.items()}


def make_gateway(storage: dict | None = None, session_data: dict | None = None, **client_kwargs):
    """A gateway over a dict-backed storage; session_data is a ready Passwork session placed into storage."""
    storage = {} if storage is None else storage
    if session_data is not None:
        storage[STORAGE_KEY] = _legacy_record(session_data)
    client_kwargs.setdefault("verify_ssl", False)
    client_kwargs.setdefault("timeout", 5)
    client = PassworkAuthClient(base_url=BASE_URL, **client_kwargs)
    return PassworkGateway(storage, client, {"SESSION_ENCRYPT_KEY": ENCRYPT_KEY}), storage


def _mock_login(requires_totp: bool = False):
    resp_mock.add(resp_mock.POST, CSRF_URL, json=_wrap({"csrfToken": "csrf1"}))
    resp_mock.add(
        resp_mock.POST,
        LOGIN_URL,
        json=_wrap({"csrfToken": "csrf2", "refreshToken": "ref1"}),
        headers={"Set-Cookie": "accessToken=acc1"},
    )
    resp_mock.add(resp_mock.GET, INFO_URL, json=_wrap({"isTwoFactorAuthEnabled": requires_totp}))
    if requires_totp:
        resp_mock.add(
            resp_mock.GET, SEARCH_URL, json=_wrap({"errors": [{"code": "twoFactorAuthRequired"}]}), status=401
        )


@contextlib.contextmanager
def _assert_raises(exc_class, code: str, http_status: int):
    """An exception of the right class with the right code/http_status and a non-empty detail."""
    with pytest.raises(exc_class) as info:
        yield info
    assert info.value.code == code, f"code={info.value.code!r}, expected {code!r}"
    assert info.value.http_status == http_status
    assert isinstance(info.value.detail, str) and info.value.detail


# ------------------------------------------------------------------
# Storage: the key and record shape are compatible with the ≤ 1.2.x format
# ------------------------------------------------------------------


class TestStorageCompatibility:
    @resp_mock.activate
    def test_login_writes_record_in_current_format(self):
        """Record after login: the same key, the same fields, the same three encrypted fields."""
        _mock_login()
        gateway, storage = make_gateway()

        gateway.login("user", "pass")

        assert set(storage) == {STORAGE_KEY}
        record = storage[STORAGE_KEY]
        assert set(record) == set(ENCRYPTED_FIELDS) | set(PLAIN_FIELDS)
        for field in ENCRYPTED_FIELDS:
            assert record[field] != _decrypted(record)[field], f"{field} lies in plaintext"
            FERNET.decrypt(record[field].encode())  # Fernet token under the same key
        assert isinstance(record["access_token_expired_at"], int)
        assert isinstance(record["refresh_token_expired_at"], int)
        assert record["requires_totp"] is False

    @resp_mock.activate
    def test_record_written_by_gateway_is_readable_by_pre_1_3_format(self):
        _mock_login()
        gateway, storage = make_gateway()

        gateway.login("user", "pass")

        plain = _decrypted(storage[STORAGE_KEY])
        assert plain["access_token"] == "acc1"
        assert plain["refresh_token"] == "ref1"
        assert plain["csrf_token"] == "csrf2"
        assert plain["requires_totp"] is False

    @resp_mock.activate
    def test_record_written_by_pre_1_3_code_is_readable_by_gateway(self):
        """Existing users are not logged out on upgrade."""
        resp_mock.add(resp_mock.GET, VAULTS_URL, json=_wrap({"items": [{"id": "v1"}]}))
        storage = {STORAGE_KEY: _legacy_record(_session())}
        gateway, _ = make_gateway(storage)

        gateway.require_session()
        assert gateway.list_vaults() == [{"id": "v1"}]
        assert resp_mock.calls[0].request.headers["Authorization"] == "Bearer acc"
        assert resp_mock.calls[0].request.headers["X-CSRF-Token"] == "csrf"

    def test_legacy_oracle_roundtrip(self):
        """_legacy_record/_decrypted on their own: encrypted ≠ plaintext, decrypts back."""
        session = _session()
        record = _legacy_record(session)

        for field in ENCRYPTED_FIELDS:
            assert record[field] != session[field], f"{field} lies in plaintext"

        assert _decrypted(record) == session


# ------------------------------------------------------------------
# login / confirm_totp
# ------------------------------------------------------------------


class TestLogin:
    @resp_mock.activate
    def test_login_without_totp_returns_false_and_stores_session(self):
        _mock_login(requires_totp=False)
        gateway, storage = make_gateway()

        assert gateway.login("user", "pass") is False
        assert _decrypted(storage[STORAGE_KEY])["requires_totp"] is False

    @resp_mock.activate
    def test_login_with_totp_returns_true_and_stores_session(self):
        _mock_login(requires_totp=True)
        gateway, storage = make_gateway()

        assert gateway.login("user", "pass") is True
        assert _decrypted(storage[STORAGE_KEY])["requires_totp"] is True

    @resp_mock.activate
    def test_login_overwrites_stale_record(self):
        _mock_login()
        gateway, storage = make_gateway(session_data=_session())
        stale = storage[STORAGE_KEY]

        gateway.login("user", "pass")

        assert storage[STORAGE_KEY] != stale
        assert _decrypted(storage[STORAGE_KEY])["access_token"] == "acc1"

    @resp_mock.activate
    def test_invalid_credentials(self):
        resp_mock.add(resp_mock.POST, CSRF_URL, json=_wrap({"csrfToken": "csrf1"}))
        resp_mock.add(resp_mock.POST, LOGIN_URL, json=_wrap({"errors": [{"code": "invalidCredentials"}]}), status=401)
        gateway, storage = make_gateway()

        with _assert_raises(PassworkAccessDenied, "invalid_credentials", 401):
            gateway.login("user", "wrong")
        assert storage == {}, "no record is created on a failed login"

    @resp_mock.activate
    def test_403_is_invalid_credentials_too(self):
        """Passwork rejection at login — always invalid_credentials 401 (the context is known to the operation)."""
        resp_mock.add(resp_mock.POST, CSRF_URL, json=_wrap({"csrfToken": "csrf1"}))
        resp_mock.add(resp_mock.POST, LOGIN_URL, json=_wrap({"errors": [{"code": "forbidden"}]}), status=403)
        gateway, storage = make_gateway()

        with _assert_raises(PassworkAccessDenied, "invalid_credentials", 401):
            gateway.login("user", "pass")
        assert storage == {}

    @resp_mock.activate
    def test_timeout(self):
        resp_mock.add(resp_mock.POST, CSRF_URL, body=requests.Timeout())
        gateway, storage = make_gateway()

        with _assert_raises(PassworkTimeout, "pw_timeout", 504):
            gateway.login("user", "pass")
        assert storage == {}

    @resp_mock.activate
    def test_non_json(self):
        resp_mock.add(resp_mock.POST, CSRF_URL, body="<html>502</html>", status=502)
        gateway, storage = make_gateway()

        with _assert_raises(PassworkBadResponse, "pw_bad_response", 502):
            gateway.login("user", "pass")
        assert storage == {}


class TestConfirmTotp:
    @resp_mock.activate
    def test_success_clears_requires_totp(self):
        resp_mock.add(resp_mock.POST, TOTP_URL, json=_wrap({}))
        gateway, storage = make_gateway(session_data=_session(requires_totp=True))

        gateway.confirm_totp("123456")

        assert _decrypted(storage[STORAGE_KEY])["requires_totp"] is False
        assert resp_mock.calls[0].request.headers["Authorization"] == "Bearer acc"

    @resp_mock.activate
    def test_invalid_code(self):
        resp_mock.add(resp_mock.POST, TOTP_URL, json=_wrap({"errors": [{"code": "invalidCode"}]}), status=401)
        gateway, storage = make_gateway(session_data=_session(requires_totp=True))

        with _assert_raises(PassworkAccessDenied, "invalid_totp", 401):
            gateway.confirm_totp("000000")
        assert _decrypted(storage[STORAGE_KEY])["requires_totp"] is True, (
            "the record is kept — the entry can be retried"
        )

    @resp_mock.activate
    def test_403_is_invalid_totp_too(self):
        resp_mock.add(resp_mock.POST, TOTP_URL, json=_wrap({"errors": [{"code": "forbidden"}]}), status=403)
        gateway, _ = make_gateway(session_data=_session(requires_totp=True))
        with _assert_raises(PassworkAccessDenied, "invalid_totp", 401):
            gateway.confirm_totp("000000")

    def test_without_record(self):
        gateway, _ = make_gateway()
        with _assert_raises(PassworkError, "pw_not_authenticated", 401):
            gateway.confirm_totp("123456")

    @resp_mock.activate
    def test_timeout(self):
        resp_mock.add(resp_mock.POST, TOTP_URL, body=requests.Timeout())
        gateway, _ = make_gateway(session_data=_session(requires_totp=True))
        with _assert_raises(PassworkTimeout, "pw_timeout", 504):
            gateway.confirm_totp("123456")

    @resp_mock.activate
    def test_non_json(self):
        resp_mock.add(resp_mock.POST, TOTP_URL, body="<html>502</html>", status=502)
        gateway, _ = make_gateway(session_data=_session(requires_totp=True))
        with _assert_raises(PassworkBadResponse, "pw_bad_response", 502):
            gateway.confirm_totp("123456")


# ------------------------------------------------------------------
# require_session: reading, extending, deleting the record
# ------------------------------------------------------------------


class TestRequireSession:
    def test_without_record(self):
        gateway, _ = make_gateway()
        with _assert_raises(PassworkError, "pw_not_authenticated", 401):
            gateway.require_session()

    @resp_mock.activate
    def test_live_session_no_refresh_no_write(self):
        gateway, storage = make_gateway(session_data=_session())
        before = dict(storage[STORAGE_KEY])

        gateway.require_session()

        assert len(resp_mock.calls) == 0
        assert storage[STORAGE_KEY] == before

    @resp_mock.activate
    def test_refreshes_when_access_token_about_to_expire(self):
        resp_mock.add(resp_mock.POST, REFRESH_URL, json=_wrap({}), headers={"Set-Cookie": "accessToken=new_acc"})
        now = int(time.time())
        gateway, storage = make_gateway(session_data=_session(access_expires=now + 30), refresh_margin=60)

        gateway.require_session()

        assert len(resp_mock.calls) == 1
        sent = resp_mock.calls[0].request
        assert json.loads(sent.body) == {"refreshToken": "ref"}
        plain = _decrypted(storage[STORAGE_KEY])
        assert plain["access_token"] == "new_acc"
        assert plain["access_token_expired_at"] >= now + 3600
        assert plain["refresh_token"] == "ref"

    @resp_mock.activate
    def test_expired_refresh_token_deletes_record(self):
        gateway, storage = make_gateway(session_data=_session(refresh_expires=int(time.time()) - 1))

        with _assert_raises(PassworkSessionExpired, "pw_session_expired", 401):
            gateway.require_session()
        assert STORAGE_KEY not in storage
        assert len(resp_mock.calls) == 0

    @pytest.mark.parametrize("status", [401, 403])
    @resp_mock.activate
    def test_rejected_refresh_deletes_record(self, status):
        """401/403 from /sessions/refresh — refresh token rejected: the record is deleted, 401 pw_session_expired."""
        resp_mock.add(resp_mock.POST, REFRESH_URL, json=_wrap({"errors": []}), status=status)
        gateway, storage = make_gateway(session_data=_session(access_expires=int(time.time()) + 30))

        with _assert_raises(PassworkSessionExpired, "pw_session_expired", 401):
            gateway.require_session()
        assert STORAGE_KEY not in storage

    @resp_mock.activate
    def test_record_is_read_and_decrypted_once_per_gateway(self):
        """The gateway lives for one HTTP request: require_session() + operations read/decrypt the record once."""

        class _CountingStorage(dict):
            reads = 0

            def get(self, key, default=None):
                self.reads += 1
                return super().get(key, default)

        resp_mock.add(resp_mock.GET, VAULTS_URL, json=_wrap({"items": []}))
        resp_mock.add(resp_mock.GET, SEARCH_URL, json=_wrap({"items": []}))
        storage = _CountingStorage()
        gateway, _ = make_gateway(storage, session_data=_session())

        gateway.require_session()
        gateway.list_vaults()
        gateway.search_items("x")

        assert storage.reads == 1
        assert [c.request.headers["Authorization"] for c in resp_mock.calls] == ["Bearer acc", "Bearer acc"]

    @resp_mock.activate
    def test_refresh_timeout_keeps_record(self):
        resp_mock.add(resp_mock.POST, REFRESH_URL, body=requests.Timeout())
        gateway, storage = make_gateway(session_data=_session(access_expires=int(time.time()) + 30))

        with _assert_raises(PassworkTimeout, "pw_timeout", 504):
            gateway.require_session()
        assert STORAGE_KEY in storage

    @resp_mock.activate
    def test_refresh_non_json_keeps_record(self):
        resp_mock.add(resp_mock.POST, REFRESH_URL, body="<html>502</html>", status=502)
        gateway, storage = make_gateway(session_data=_session(access_expires=int(time.time()) + 30))

        with _assert_raises(PassworkBadResponse, "pw_bad_response", 502):
            gateway.require_session()
        assert STORAGE_KEY in storage

    def test_invalid_token_deletes_record_and_warns(self, caplog):
        """SESSION_ENCRYPT_KEY was changed: the record is deleted, a warning is logged, the response is "login required"."""
        session = _session(access_token="ACCESS-TOKEN-VALUE", refresh_token="REFRESH-TOKEN-VALUE")
        record = _legacy_record(session, key=Fernet.generate_key())
        storage = {STORAGE_KEY: record}
        gateway, _ = make_gateway(storage)

        with caplog.at_level(logging.WARNING, logger="netbox_passwork"):
            with _assert_raises(PassworkError, "pw_not_authenticated", 401):
                gateway.require_session()

        assert STORAGE_KEY not in storage
        assert any(r.levelno == logging.WARNING for r in caplog.records)
        # The Passwork session is never logged — neither in plaintext nor encrypted
        assert "TOKEN-VALUE" not in caplog.text
        assert record["access_token"] not in caplog.text

    def test_unexpected_exception_is_not_swallowed(self):
        """Other exceptions while reading the record are not masked as 401."""
        record = _legacy_record(_session())
        del record["access_token_expired_at"]
        gateway, _ = make_gateway({STORAGE_KEY: record})

        with pytest.raises(KeyError):
            gateway.require_session()


# ------------------------------------------------------------------
# get_item / list_vaults / search_items: mapping Passwork failures
# ------------------------------------------------------------------


def _get_item(gateway):
    return gateway.get_item("pw123")


def _list_vaults(gateway):
    return gateway.list_vaults()


def _search_items(gateway):
    return gateway.search_items("router")


READ_OPERATIONS = [
    pytest.param(_get_item, ITEM_URL, id="get_item"),
    pytest.param(_list_vaults, VAULTS_URL, id="list_vaults"),
    pytest.param(_search_items, SEARCH_URL, id="search_items"),
]


class TestReadOperations:
    @resp_mock.activate
    def test_get_item_decodes_password_and_custom_fields(self):
        resp_mock.add(
            resp_mock.GET,
            ITEM_URL,
            json=_wrap(
                {
                    "id": "pw123",
                    "name": "Router",
                    "passwordEncrypted": base64.b64encode(b"secret").decode(),
                    "customs": [
                        {
                            "name": base64.b64encode(b"pin").decode(),
                            "value": base64.b64encode(b"1234").decode(),
                            "type": base64.b64encode(b"password").decode(),
                        }
                    ],
                }
            ),
        )
        gateway, _ = make_gateway(session_data=_session())

        item = gateway.get_item("pw123")

        assert item["name"] == "Router"
        assert item["password"] == "secret"
        assert item["custom_fields"] == [{"name": "pin", "value": "1234", "is_secret": True, "type": "password"}]

    @resp_mock.activate
    def test_list_vaults_returns_items(self):
        resp_mock.add(resp_mock.GET, VAULTS_URL, json=_wrap({"items": [{"id": "v1", "name": "Vault"}]}))
        gateway, _ = make_gateway(session_data=_session())
        assert gateway.list_vaults() == [{"id": "v1", "name": "Vault"}]

    @resp_mock.activate
    def test_search_items_returns_items_and_encodes_query(self):
        resp_mock.add(resp_mock.GET, SEARCH_URL, json=_wrap({"items": [{"id": "pw1"}]}))
        gateway, _ = make_gateway(session_data=_session())

        assert gateway.search_items("a&b") == [{"id": "pw1"}]
        assert "%26" in resp_mock.calls[0].request.url

    @pytest.mark.parametrize(("op", "url"), READ_OPERATIONS)
    def test_without_record(self, op, url):
        gateway, _ = make_gateway()
        with _assert_raises(PassworkError, "pw_not_authenticated", 401):
            op(gateway)

    @pytest.mark.parametrize(("op", "url"), READ_OPERATIONS)
    @resp_mock.activate
    def test_401_maps_to_session_expired(self, op, url):
        resp_mock.add(resp_mock.GET, url, json=_wrap({"errors": []}), status=401)
        gateway, storage = make_gateway(session_data=_session())
        with _assert_raises(PassworkSessionExpired, "pw_session_expired", 401):
            op(gateway)
        assert STORAGE_KEY in storage, 'a 401 from an operation (incl. "TOTP needed") does not delete the record'

    @pytest.mark.parametrize(("op", "url"), READ_OPERATIONS)
    @resp_mock.activate
    def test_403_maps_to_access_denied(self, op, url):
        resp_mock.add(resp_mock.GET, url, json=_wrap({"errors": []}), status=403)
        gateway, _ = make_gateway(session_data=_session())
        with _assert_raises(PassworkAccessDenied, "pw_access_denied", 403):
            op(gateway)

    @pytest.mark.parametrize(("op", "url"), READ_OPERATIONS)
    @resp_mock.activate
    def test_timeout_maps_to_pw_timeout(self, op, url):
        resp_mock.add(resp_mock.GET, url, body=requests.Timeout())
        gateway, _ = make_gateway(session_data=_session())
        with _assert_raises(PassworkTimeout, "pw_timeout", 504):
            op(gateway)

    @pytest.mark.parametrize(("op", "url"), READ_OPERATIONS)
    @resp_mock.activate
    def test_non_json_maps_to_bad_response(self, op, url):
        resp_mock.add(resp_mock.GET, url, body="<html>502 Bad Gateway</html>", status=502)
        gateway, _ = make_gateway(session_data=_session())
        with _assert_raises(PassworkBadResponse, "pw_bad_response", 502):
            op(gateway)

    @pytest.mark.parametrize(("op", "url"), READ_OPERATIONS)
    @resp_mock.activate
    def test_refreshes_before_operation(self, op, url):
        """An operation performed with the Passwork session extends the access token itself."""
        resp_mock.add(resp_mock.POST, REFRESH_URL, json=_wrap({}), headers={"Set-Cookie": "accessToken=new_acc"})
        resp_mock.add(resp_mock.GET, url, json=_wrap({"items": [], "customs": []}))
        gateway, storage = make_gateway(session_data=_session(access_expires=int(time.time()) + 30))

        op(gateway)

        assert [c.request.url.split("?")[0] for c in resp_mock.calls] == [REFRESH_URL, url]
        assert resp_mock.calls[1].request.headers["Authorization"] == "Bearer new_acc"
        assert _decrypted(storage[STORAGE_KEY])["access_token"] == "new_acc"


# ------------------------------------------------------------------
# list_folder_contents: subfolders and passwords of a vault/folder
# ------------------------------------------------------------------


def _folders_body():
    """A flat vault folder tree (Api reference §11.5 shape): parentFolderId links children."""
    return _wrap(
        {
            "items": [
                {"id": "f1", "name": "Network", "vaultId": "v1", "parentFolderId": None},
                {"id": "f2", "name": "Nested", "vaultId": "v1", "parentFolderId": "f1"},
                {"id": "f3", "name": "Deep", "vaultId": "v1", "parentFolderId": "f2"},
            ]
        }
    )


class TestListFolderContents:
    @resp_mock.activate
    def test_vault_node_returns_root_folders_and_vault_items(self):
        """Vault node: the vault's root folders (parentFolderId=null) + all the vault's passwords."""
        resp_mock.add(resp_mock.GET, FOLDERS_URL, json=_folders_body())
        resp_mock.add(resp_mock.GET, ITEMS_URL, json=_wrap({"items": [{"id": "pw1", "name": "Router"}]}))
        gateway, _ = make_gateway(session_data=_session())

        contents = gateway.list_folder_contents("v1")

        assert contents == {
            "folders": [{"id": "f1", "name": "Network"}],
            "items": [{"id": "pw1", "name": "Router"}],
        }
        folders_url, items_url = (c.request.url for c in resp_mock.calls)
        assert folders_url == f"{FOLDERS_URL}?vaultId=v1"
        assert items_url == f"{ITEMS_URL}?vaultId=v1", "vault node lists items with no folderId (whole vault)"

    @resp_mock.activate
    def test_folder_node_returns_children_and_folder_items(self):
        """Folder node: only the folder's direct subfolders + the passwords in that folder."""
        resp_mock.add(resp_mock.GET, FOLDERS_URL, json=_folders_body())
        resp_mock.add(resp_mock.GET, ITEMS_URL, json=_wrap({"items": [{"id": "pw2", "name": "Switch"}]}))
        gateway, _ = make_gateway(session_data=_session())

        contents = gateway.list_folder_contents("v1", "f1")

        assert contents == {
            "folders": [{"id": "f2", "name": "Nested"}],
            "items": [{"id": "pw2", "name": "Switch"}],
        }
        items_url = resp_mock.calls[1].request.url
        assert items_url == f"{ITEMS_URL}?vaultId=v1&folderId=f1"

    @resp_mock.activate
    def test_ids_are_url_encoded(self):
        """`&`/`=` in the vault/folder ids don't inject query parameters (H1)."""
        resp_mock.add(resp_mock.GET, FOLDERS_URL, json=_wrap({"items": []}))
        resp_mock.add(resp_mock.GET, ITEMS_URL, json=_wrap({"items": []}))
        gateway, _ = make_gateway(session_data=_session())

        gateway.list_folder_contents("v&1", "f&1")

        folders_url, items_url = (c.request.url for c in resp_mock.calls)
        assert "v%261" in folders_url and "&1" not in folders_url.split("?", 1)[1]
        assert "vaultId=v%261" in items_url and "folderId=f%261" in items_url

    @resp_mock.activate
    def test_passwords_come_from_listing_not_search(self):
        """Regression (#15): the picker never uses the text-search endpoint — it lists items."""
        resp_mock.add(resp_mock.GET, FOLDERS_URL, json=_wrap({"items": []}))
        resp_mock.add(resp_mock.GET, ITEMS_URL, json=_wrap({"items": []}))
        gateway, _ = make_gateway(session_data=_session())

        gateway.list_folder_contents("v1")

        assert all("/items/search" not in c.request.url for c in resp_mock.calls)

    @pytest.mark.parametrize(
        ("status", "exc", "code", "http_status"),
        [
            (401, PassworkSessionExpired, "pw_session_expired", 401),
            (403, PassworkAccessDenied, "pw_access_denied", 403),
        ],
    )
    @resp_mock.activate
    def test_folders_auth_failure_propagates(self, status, exc, code, http_status):
        """A 401/403 on the folder listing surfaces as the uniform Passwork error (no degradation)."""
        resp_mock.add(resp_mock.GET, FOLDERS_URL, json=_wrap({"errors": []}), status=status)
        gateway, gw_storage = make_gateway(session_data=_session())
        with _assert_raises(exc, code, http_status):
            gateway.list_folder_contents("v1")
        if status == 401:
            assert STORAGE_KEY in gw_storage, "a 401 from an operation does not delete the record"

    @resp_mock.activate
    def test_items_bad_response_propagates(self):
        """A non-JSON response on the item listing surfaces as pw_bad_response."""
        resp_mock.add(resp_mock.GET, FOLDERS_URL, json=_wrap({"items": []}))
        resp_mock.add(resp_mock.GET, ITEMS_URL, body="<html>502</html>", status=502)
        gateway, _ = make_gateway(session_data=_session())
        with _assert_raises(PassworkBadResponse, "pw_bad_response", 502):
            gateway.list_folder_contents("v1")

    def test_without_record_raises_not_authenticated(self):
        gateway, _ = make_gateway()
        with _assert_raises(PassworkError, "pw_not_authenticated", 401):
            gateway.list_folder_contents("v1")


# ------------------------------------------------------------------
# Building the gateway per request — the single composition point
# ------------------------------------------------------------------


class TestBuildGateway:
    def test_builds_gateway_over_request_session(self):
        request = RequestFactory().get("/")
        request.session = {}

        gateway = build_gateway(request)

        assert isinstance(gateway, PassworkGateway)
        with _assert_raises(PassworkError, "pw_not_authenticated", 401):
            gateway.require_session()

    def test_gateway_uses_plugin_config(self):
        """Key and record — from PLUGINS_CONFIG: a record created with this key is readable."""
        key = Fernet.generate_key()
        request = RequestFactory().get("/")
        request.session = {STORAGE_KEY: _legacy_record(_session(), key=key)}
        with override_settings(
            PLUGINS_CONFIG={"netbox_passwork": {"PASSWORK_URL": BASE_URL, "SESSION_ENCRYPT_KEY": key}}
        ):
            gateway = build_gateway(request)
            gateway.require_session()  # does not raise: decrypted with the same key
        assert STORAGE_KEY in request.session

    @resp_mock.activate
    def test_client_settings_come_from_plugin_config(self):
        """URL, margin — from PLUGINS_CONFIG: with a larger margin the gateway refreshes the token at PASSWORK_URL."""
        key = Fernet.generate_key()
        resp_mock.add(resp_mock.POST, REFRESH_URL, json=_wrap({}), headers={"Set-Cookie": "accessToken=new_acc"})
        request = RequestFactory().get("/")
        request.session = {STORAGE_KEY: _legacy_record(_session(), key=key)}
        cfg = {"PASSWORK_URL": BASE_URL, "SESSION_ENCRYPT_KEY": key, "TOKEN_REFRESH_MARGIN": 7200}
        with override_settings(PLUGINS_CONFIG={"netbox_passwork": cfg}):
            build_gateway(request).require_session()
        assert len(resp_mock.calls) == 1
        assert _decrypted(request.session[STORAGE_KEY], key=key)["access_token"] == "new_acc"


# ------------------------------------------------------------------
# FakeGateway does not drift from the real interface
# ------------------------------------------------------------------


def _public_operations(cls) -> dict[str, list[str]]:
    return {
        name: [p for p in inspect.signature(member).parameters if p != "self"]
        for name, member in inspect.getmembers(cls, inspect.isfunction)
        if not name.startswith("_")
    }


class TestFakeGatewayInterface:
    def test_same_public_operations_and_parameters(self):
        assert _public_operations(FakeGateway) == _public_operations(PassworkGateway)

    def test_exactly_seven_operations(self):
        assert set(_public_operations(PassworkGateway)) == {
            "login",
            "confirm_totp",
            "get_item",
            "list_vaults",
            "search_items",
            "list_folder_contents",
            "require_session",
        }

    def test_fake_default_results(self):
        fake = FakeGateway()
        assert fake.login("u", "p") is False
        assert fake.confirm_totp("1") is None
        assert fake.get_item("x") == {}
        assert fake.list_vaults() == []
        assert fake.search_items("q") == []
        assert fake.list_folder_contents("v1") == {"folders": [], "items": []}
        assert fake.require_session() is None
        assert [c[0] for c in fake.calls] == [
            "login",
            "confirm_totp",
            "get_item",
            "list_vaults",
            "search_items",
            "list_folder_contents",
            "require_session",
        ]

    def test_fake_programmable_results_and_errors(self):
        fake = FakeGateway(login=True, get_item={"name": "x"}, list_vaults=PassworkTimeout())
        assert fake.login("u", "p") is True
        assert fake.get_item("pw1") == {"name": "x"}
        with pytest.raises(PassworkTimeout):
            fake.list_vaults()
        assert fake.calls == [("login", "u", "p"), ("get_item", "pw1"), ("list_vaults",)]

    def test_fake_rejects_unknown_operation(self):
        with pytest.raises(TypeError):
            FakeGateway(logout=None)
