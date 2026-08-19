import pytest

from netbox_passwork.exceptions import (
    PassworkAccessDenied,
    PassworkBadResponse,
    PassworkError,
    PassworkSessionExpired,
    PassworkTimeout,
)


class TestExceptions:
    def test_base_error_is_exception(self):
        assert issubclass(PassworkError, Exception)

    @pytest.mark.parametrize(
        "exc_class",
        [PassworkSessionExpired, PassworkAccessDenied, PassworkTimeout, PassworkBadResponse],
    )
    def test_all_inherit_from_passwork_error(self, exc_class):
        assert issubclass(exc_class, PassworkError)
        with pytest.raises(PassworkError):
            raise exc_class("boom")

    @pytest.mark.parametrize(
        ("exc_class", "code", "http_status"),
        [
            (PassworkSessionExpired, "pw_session_expired", 401),
            (PassworkAccessDenied, "pw_access_denied", 403),
            (PassworkTimeout, "pw_timeout", 504),
            (PassworkBadResponse, "pw_bad_response", 502),
        ],
    )
    def test_defaults(self, exc_class, code, http_status):
        exc = exc_class()
        assert exc.code == code
        assert exc.http_status == http_status
        assert isinstance(exc.detail, str) and exc.detail

    def test_detail_from_message(self):
        exc = PassworkTimeout("GET /x timed out")
        assert exc.detail == "GET /x timed out"
        assert str(exc) == "GET /x timed out"

    def test_operation_may_override_code_and_status(self):
        """The rejection context is known to the operation: login → invalid_credentials 401 (ADR-0001)."""
        exc = PassworkAccessDenied("Invalid credentials", code="invalid_credentials", http_status=401)
        assert exc.code == "invalid_credentials"
        assert exc.http_status == 401
        assert exc.detail == "Invalid credentials"
        # class defaults are unaffected
        assert PassworkAccessDenied().code == "pw_access_denied"
        assert PassworkAccessDenied().http_status == 403

    def test_base_error_accepts_explicit_fields(self):
        exc = PassworkError("nope", code="pw_custom", http_status=418)
        assert (exc.code, exc.http_status, exc.detail) == ("pw_custom", 418, "nope")
