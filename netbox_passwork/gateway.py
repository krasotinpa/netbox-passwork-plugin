"""
Passwork gateway — the single point through which the plugin talks to Passwork on
behalf of the Passwork session (see docs/adr/0001-passwork-gateway-not-middleware.md).

The module owns everything related to the Passwork session: it is the only place that
reads the plugin config, the only place that Fernet-encrypts its fields, reads/writes/
deletes its record in storage (in production, the request's Django session), refreshes
the access token, and provides six domain operations. Passwork failures are raised as
``PassworkError`` with ``code``/``http_status`` — the failure context is known to the operation.
"""

import logging

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

from netbox_passwork.exceptions import PassworkError, PassworkSessionExpired
from netbox_passwork.passwork_client import PassworkAuthClient

logger = logging.getLogger("netbox_passwork")

# The storage key and record shape are byte-for-byte compatible with pre-1.3.0
# versions: existing users don't get logged out on upgrade.
_STORAGE_KEY = "pw_session"
_ENCRYPTED_FIELDS = ("access_token", "refresh_token", "csrf_token")


def _not_authenticated(detail: str) -> PassworkError:
    return PassworkError(detail, code="pw_not_authenticated", http_status=401)


class PassworkGateway:
    """
    Six operations on behalf of the Passwork session, over storage with a ``dict`` interface.

    ``storage`` — where the Passwork session record lives (``request.session`` in
    production, a plain ``dict`` in tests); ``client`` — the HTTP implementation of the
    Passwork API; ``config`` — the plugin config (``PLUGINS_CONFIG["netbox_passwork"]``),
    from which the gateway takes ``SESSION_ENCRYPT_KEY``.
    """

    def __init__(self, storage, client: PassworkAuthClient, config):
        self._storage = storage
        self._client = client
        key = config["SESSION_ENCRYPT_KEY"]
        self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
        # The gateway lives for a single HTTP request: the Passwork session that's been
        # read (and refreshed if needed) is reused by all operations of the request —
        # without re-decrypting the record
        self._passwork_session: dict | None = None

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    def login(self, username: str, password: str) -> bool:
        """Log in to Passwork; saves the Passwork session. Returns whether TOTP is required."""
        passwork_session = self._client.login(username, password)
        self._write(passwork_session)
        return bool(passwork_session["requires_totp"])

    def confirm_totp(self, code: str) -> None:
        """Confirms TOTP for the saved Passwork session."""
        passwork_session = self._client.confirm_totp(code, self._load())
        self._write(passwork_session)

    def get_item(self, pw_id: str) -> dict:
        """Passwork item with the password and custom fields decoded."""
        return self._client.get_item(pw_id, self._load())

    def list_vaults(self) -> list:
        """List of Passwork vaults."""
        return self._client.list_vaults(self._load())

    def search_items(self, query: str) -> list:
        """Search Passwork items (the query is URL-encoded by the client)."""
        return self._client.search_items(query, self._load())

    def require_session(self) -> None:
        """Guarantees the Passwork session exists and hasn't expired (refreshing it if needed)."""
        self._load()

    # ------------------------------------------------------------------
    # Passwork session in storage
    # ------------------------------------------------------------------

    def _load(self) -> dict:
        """
        Reads and, if needed, refreshes the Passwork session.

        Known failures: no record → 401 ``pw_not_authenticated``; refresh token expired
        or rejected → record is deleted, 401 ``pw_session_expired``; ``InvalidToken``
        (``SESSION_ENCRYPT_KEY`` changed) → record is deleted, warning, 401
        ``pw_not_authenticated``; timeout/non-JSON during refresh → 504/502.
        Other exceptions are not swallowed. The result is cached for the gateway's lifetime.
        """
        if self._passwork_session is not None:
            return self._passwork_session
        record = self._storage.get(_STORAGE_KEY)
        if record is None:
            raise _not_authenticated("Passwork session not found")
        try:
            passwork_session = self._decrypt(record)
        except InvalidToken:
            self._delete()
            logger.warning(
                "Passwork session record could not be decrypted (SESSION_ENCRYPT_KEY changed?); record dropped"
            )
            raise _not_authenticated("Passwork session could not be decrypted") from None

        before = dict(passwork_session)
        try:
            passwork_session = self._client.refresh_if_needed(passwork_session)
        except PassworkSessionExpired:
            self._delete()
            raise
        # Rewrite the record only if the refresh changed it — avoids unnecessary session saves
        if passwork_session != before:
            self._write(passwork_session)
        self._passwork_session = passwork_session
        return passwork_session

    def _write(self, passwork_session: dict) -> None:
        # Assigning the key by itself marks the Django session as modified
        self._storage[_STORAGE_KEY] = self._encrypt(passwork_session)
        self._passwork_session = passwork_session

    def _delete(self) -> None:
        self._storage.pop(_STORAGE_KEY, None)
        self._passwork_session = None

    def _encrypt(self, passwork_session: dict) -> dict:
        return {
            k: self._fernet.encrypt(str(v).encode()).decode() if k in _ENCRYPTED_FIELDS else v
            for k, v in passwork_session.items()
        }

    def _decrypt(self, record: dict) -> dict:
        return {
            k: self._fernet.decrypt(v.encode()).decode() if k in _ENCRYPTED_FIELDS else v for k, v in record.items()
        }


def build_gateway(request) -> PassworkGateway:
    """
    Builds the gateway from an HTTP request — the single point of composition and the
    only place that reads the plugin config.
    """
    config = settings.PLUGINS_CONFIG["netbox_passwork"]
    client = PassworkAuthClient(
        base_url=config["PASSWORK_URL"],
        verify_ssl=config.get("PASSWORK_VERIFY_SSL", True),
        timeout=config.get("PASSWORK_REQUEST_TIMEOUT", 5),
        refresh_margin=config.get("TOKEN_REFRESH_MARGIN", 60),
    )
    return PassworkGateway(request.session, client, config)
