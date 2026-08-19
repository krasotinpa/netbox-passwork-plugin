import base64
import json
import logging
import time
import urllib.parse

import requests
import urllib3

from netbox_passwork.exceptions import (
    PassworkAccessDenied,
    PassworkBadResponse,
    PassworkSessionExpired,
    PassworkTimeout,
)

logger = logging.getLogger("netbox_passwork")


def _decode(r: requests.Response) -> dict:
    try:
        raw = r.json()
    except Exception:
        raise PassworkBadResponse(f"Non-JSON response from Passwork: HTTP {r.status_code}")
    if isinstance(raw, dict) and raw.get("format") == "base64":
        return json.loads(base64.b64decode(raw["content"]).decode())
    return raw


def _b64d(s):
    if not s:
        return ""
    try:
        return base64.b64decode(s).decode("utf-8")
    except Exception:
        return s


class PassworkAuthClient:
    """
    Passwork API v1, X-Browser-Mode.
    Based on a working authentication script.

    A pure HTTP implementation with no Django: everything needed (base URL, SSL
    verification, timeout, refresh margin) comes through the constructor.
    """

    def __init__(
        self,
        base_url: str,
        verify_ssl: bool = True,
        timeout: int = 5,
        refresh_margin: int = 60,
    ):
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.refresh_margin = refresh_margin
        self._session = requests.Session()
        self._session.verify = verify_ssl
        if not self.verify_ssl:
            urllib3.disable_warnings()

    def _base_headers(self, csrf_token: str = "") -> dict:
        h = {"X-Browser-Mode": "1", "X-Master-Key-Hash": ""}
        if csrf_token:
            h["X-CSRF-Token"] = csrf_token
        return h

    def _auth_headers(self, session_data: dict) -> dict:
        headers = self._base_headers(session_data["csrf_token"])
        headers["Authorization"] = f"Bearer {session_data['access_token']}"
        return headers

    def _post(self, path: str, data: dict, headers: dict) -> tuple:
        try:
            r = self._session.post(
                f"{self.base_url}{path}",
                json=data,
                headers=headers,
                timeout=self.timeout,
            )
            return _decode(r), r
        except requests.Timeout:
            raise PassworkTimeout(f"POST {path} timed out")

    def _get(self, path: str, headers: dict) -> tuple:
        try:
            r = self._session.get(
                f"{self.base_url}{path}",
                headers=headers,
                timeout=self.timeout,
            )
            return _decode(r), r
        except requests.Timeout:
            raise PassworkTimeout(f"GET {path} timed out")

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def login(self, username: str, password: str) -> dict:
        # Step 1: CSRF token
        headers = self._base_headers()
        data, r = self._post("/api/v1/csrf-tokens/generate", {}, headers)
        if "errors" in data:
            raise PassworkAccessDenied(f"CSRF error: {data['errors']}", code="invalid_credentials", http_status=401)
        csrf_token = data.get("csrfToken", "")
        headers = self._base_headers(csrf_token)

        # Step 2: Login
        data, r = self._post(
            "/api/v1/users/login",
            {"username": username, "password": password, "hostname": ""},
            headers,
        )
        if "errors" in data:
            raise PassworkAccessDenied("Invalid credentials", code="invalid_credentials", http_status=401)

        # csrfToken is refreshed after login
        csrf_token = data.get("csrfToken", csrf_token)
        refresh_token = data.get("refreshToken", "")
        # accessToken arrives in a cookie
        access_token = urllib.parse.unquote(self._session.cookies.get("accessToken", ""))

        now = int(time.time())
        session_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "csrf_token": csrf_token,
            "access_token_expired_at": now + 3600,
            "refresh_token_expired_at": now + 86400,
            "requires_totp": False,
        }

        # Step 3: Check whether 2FA is required
        headers = self._auth_headers(session_data)
        info_data, info_r = self._get("/api/v1/users/info", headers)

        # Check via the isTwoFactorAuthEnabled field
        # and via a test request — if 401 twoFactorAuthRequired → TOTP is needed
        requires_totp = False
        if isinstance(info_data, dict):
            if info_data.get("isTwoFactorAuthEnabled"):
                # Check whether TOTP is actually required right now
                test_data, test_r = self._get(
                    "/api/v1/items/search?query=_totp_check_",
                    headers,
                )
                if test_r.status_code == 401:
                    errors = test_data.get("errors", []) if isinstance(test_data, dict) else []
                    if any(e.get("code") == "twoFactorAuthRequired" for e in errors):
                        requires_totp = True

        session_data["requires_totp"] = requires_totp
        return session_data

    def confirm_totp(self, code: str, session_data: dict) -> dict:
        data, r = self._post(
            "/api/v1/users/2fa/totp/authorize",
            {"code": code},
            self._auth_headers(session_data),
        )
        if r.status_code == 401 or "errors" in data:
            raise PassworkAccessDenied("Invalid TOTP code", code="invalid_totp", http_status=401)

        session_data["requires_totp"] = False
        return session_data

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def refresh_if_needed(self, session_data: dict) -> dict:
        now = int(time.time())

        if now >= session_data["refresh_token_expired_at"]:
            raise PassworkSessionExpired("Refresh token expired")

        if session_data["access_token_expired_at"] - now >= self.refresh_margin:
            return session_data

        # Refresh the access token
        headers = {"Authorization": f"Bearer {session_data['access_token']}"}
        try:
            r = self._session.post(
                f"{self.base_url}/api/v1/sessions/refresh",
                json={"refreshToken": session_data["refresh_token"]},
                headers=headers,
                timeout=self.timeout,
            )
        except requests.Timeout:
            raise PassworkTimeout("Token refresh timed out")

        if r.status_code in (401, 403):
            raise PassworkSessionExpired("Refresh token rejected")

        _decode(r)  # refresh cookies from the response
        # accessToken is refreshed in the cookie
        new_access = urllib.parse.unquote(self._session.cookies.get("accessToken", session_data["access_token"]))
        session_data["access_token"] = new_access
        session_data["access_token_expired_at"] = now + 3600
        return session_data

    # ------------------------------------------------------------------
    # Operations on behalf of the Passwork session
    # ------------------------------------------------------------------

    def _get_as_session(self, path: str, session_data: dict) -> tuple:
        """GET on behalf of the Passwork session: 401 → session expired, 403 → access denied."""
        data, r = self._get(path, self._auth_headers(session_data))
        logger.debug("GET %s status=%s", path, r.status_code)
        if r.status_code == 401:
            raise PassworkSessionExpired(f"Token expired or TOTP required for {path}")
        if r.status_code == 403:
            raise PassworkAccessDenied(f"Access denied for {path}")
        return data, r

    def get_item(self, pw_id: str, session_data: dict) -> dict:
        data, r = self._get_as_session(f"/api/v1/items/{pw_id}", session_data)
        if r.status_code == 404:
            return {}

        # CSE is disabled — passwordEncrypted is base64(plaintext)
        if isinstance(data, dict) and data.get("passwordEncrypted"):
            try:
                data["password"] = base64.b64decode(data["passwordEncrypted"]).decode("utf-8")
            except Exception:
                data["password"] = None
        else:
            data["password"] = None

        # customs → custom_fields
        # Passwork encodes name/value/type as base64
        customs = data.get("customs", []) or []
        data["custom_fields"] = []
        for c in customs:
            name = _b64d(c.get("name", ""))
            value = _b64d(c.get("value", ""))
            field_type = _b64d(c.get("type", "text"))
            is_secret = field_type in ("password", "totp")
            data["custom_fields"].append(
                {
                    "name": name,
                    "value": value,
                    "is_secret": is_secret,
                    "type": field_type,
                }
            )

        return data

    def _get_items(self, path: str, session_data: dict) -> list:
        data, _ = self._get_as_session(path, session_data)
        return data.get("items", []) if isinstance(data, dict) else []

    def list_vaults(self, session_data: dict) -> list:
        """List of Passwork vaults."""
        return self._get_items("/api/v1/vaults", session_data)

    def search_items(self, query: str, session_data: dict) -> list:
        """Search items; the query is URL-encoded (H1: `&`/`=` don't inject parameters)."""
        return self._get_items(f"/api/v1/items/search?query={urllib.parse.quote(query, safe='')}", session_data)
