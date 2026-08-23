import base64
import json

import pytest
import responses as resp_mock
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from responses import matchers

from netbox_passwork.exceptions import PassworkError
from netbox_passwork.models import PassworkBinding

User = get_user_model()


def grant_netbox_perm(user, action):
    """Grants a permission via NetBox ObjectPermission (the only working way)."""
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


@pytest.fixture
def user(db):
    return User.objects.create_user(username="testuser", password="testpass123")


@pytest.fixture
def other_user(db):
    return User.objects.create_user(username="otheruser", password="testpass123")


@pytest.fixture
def binding(db, user):
    b = PassworkBinding(
        object_type="device",
        object_id=1,
        passwork_item_id="abc123",
        created_by=user,
    )
    b.save()
    return b


@pytest.fixture(scope="session")
def django_db_setup():
    """Use the existing test DB without recreating it."""
    pass


class FakeGateway:
    """
    A programmable Passwork gateway for view tests: the same eight operations as
    ``PassworkGateway`` (interface match is verified by a test).

    Arguments are operation outcomes by name: a value is returned, an exception
    instance is raised. Calls accumulate in ``calls`` as ``(operation, *args)``.
    Injected into a view through the ``as_view(gateway_factory=lambda request: fake)`` seam.
    """

    _DEFAULTS = {
        "login": False,
        "confirm_totp": None,
        "get_item": {},
        "list_vaults": [],
        "search_items": [],
        "list_folder_contents": {"folders": [], "items": []},
        "list_vault_folders": [],
        "require_session": None,
    }

    def __init__(self, **outcomes):
        unknown = set(outcomes) - set(self._DEFAULTS)
        if unknown:
            raise TypeError(f"FakeGateway: unknown operations {sorted(unknown)}")
        self._outcomes = {**self._DEFAULTS, **outcomes}
        self.calls: list[tuple] = []

    def _run(self, operation: str, *args):
        self.calls.append((operation, *args))
        outcome = self._outcomes[operation]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def login(self, username: str, password: str) -> bool:
        return self._run("login", username, password)

    def confirm_totp(self, code: str) -> None:
        return self._run("confirm_totp", code)

    def get_item(self, pw_id: str) -> dict:
        return self._run("get_item", pw_id)

    def list_vaults(self) -> list:
        return self._run("list_vaults")

    def search_items(self, query: str, vault_id: str | None = None) -> list:
        return self._run("search_items", query, vault_id)

    def list_folder_contents(self, vault_id: str, folder_id: str | None = None) -> dict:
        return self._run("list_folder_contents", vault_id, folder_id)

    def list_vault_folders(self, vault_id: str) -> list:
        return self._run("list_vault_folders", vault_id)

    def require_session(self) -> None:
        return self._run("require_session")


def no_passwork_session() -> PassworkError:
    """``require_session`` failure when there is no Passwork session record — as the real gateway does (401 pw_not_authenticated)."""
    return PassworkError("Passwork session not found", code="pw_not_authenticated", http_status=401)


# ---------------------------------------------------------------------------
# Passwork on ``responses`` — for end-to-end scenarios against the real ``build_gateway``
# ---------------------------------------------------------------------------

PASSWORK_URL = "https://passwork.test"


def wrap_passwork_response(data: dict) -> dict:
    """Wrap the response in base64, the way Passwork does."""
    return {"format": "base64", "content": base64.b64encode(json.dumps(data).encode()).decode()}


def mock_passwork_login(requires_totp: bool = False):
    """
    Registers Passwork login responses on the active ``responses``: CSRF → login
    (access token ``acc1`` in a cookie, CSRF ``csrf2``, refresh ``ref1``) → users/info;
    with ``requires_totp`` — also a 401 ``twoFactorAuthRequired`` on the test search.
    """
    resp_mock.add(
        resp_mock.POST,
        f"{PASSWORK_URL}/api/v1/csrf-tokens/generate",
        json=wrap_passwork_response({"csrfToken": "csrf1"}),
    )
    resp_mock.add(
        resp_mock.POST,
        f"{PASSWORK_URL}/api/v1/users/login",
        json=wrap_passwork_response({"csrfToken": "csrf2", "refreshToken": "ref1"}),
        headers={"Set-Cookie": "accessToken=acc1"},
    )
    resp_mock.add(
        resp_mock.GET,
        f"{PASSWORK_URL}/api/v1/users/info",
        json=wrap_passwork_response({"isTwoFactorAuthEnabled": requires_totp}),
    )
    if requires_totp:
        # Only the test login search (query=_totp_check_): picker search in the same scenario is not intercepted
        resp_mock.add(
            resp_mock.GET,
            f"{PASSWORK_URL}/api/v1/items/search",
            match=[matchers.query_param_matcher({"query": "_totp_check_"})],
            json=wrap_passwork_response({"errors": [{"code": "twoFactorAuthRequired"}]}),
            status=401,
        )
