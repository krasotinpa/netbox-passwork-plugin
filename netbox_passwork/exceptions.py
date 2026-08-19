class PassworkError(Exception):
    """
    Base exception of the Passwork gateway: a Passwork failure carrying HTTP meaning.

    ``code`` and ``http_status`` are what goes into the plugin's JSON response; ``detail``
    is a human-readable explanation. Subclasses set the defaults, and an operation that
    knows the failure context (login, TOTP, reading a secret) may override them when
    raising (ADR-0001).
    """

    code = "pw_error"
    http_status = 502
    detail = "Passwork error"

    def __init__(self, detail: str | None = None, *, code: str | None = None, http_status: int | None = None):
        if detail is not None:
            self.detail = detail
        if code is not None:
            self.code = code
        if http_status is not None:
            self.http_status = http_status
        super().__init__(self.detail)


class PassworkSessionExpired(PassworkError):
    """Refresh token expired or was rejected — a new login is required."""

    code = "pw_session_expired"
    http_status = 401
    detail = "Passwork session expired"


class PassworkAccessDenied(PassworkError):
    """Passwork denied access (403 for a secret; invalid credentials on login/TOTP)."""

    code = "pw_access_denied"
    http_status = 403
    detail = "Passwork access denied"


class PassworkTimeout(PassworkError):
    """Passwork did not respond within PASSWORK_REQUEST_TIMEOUT seconds."""

    code = "pw_timeout"
    http_status = 504
    detail = "Passwork timeout"


class PassworkBadResponse(PassworkError):
    """Passwork returned a response that isn't JSON (e.g. a proxy error HTML page)."""

    code = "pw_bad_response"
    http_status = 502
    detail = "Passwork returned a non-JSON response"
