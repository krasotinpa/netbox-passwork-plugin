import pytest
from django.test import RequestFactory

from netbox_passwork.utils import get_client_ip


@pytest.mark.django_db
class TestGetClientIp:
    def setup_method(self):
        self.factory = RequestFactory()

    def test_remote_addr(self):
        request = self.factory.get("/")
        request.META["REMOTE_ADDR"] = "192.168.1.1"
        assert get_client_ip(request) == "192.168.1.1"

    def test_x_forwarded_for_single(self):
        request = self.factory.get("/")
        request.META["HTTP_X_FORWARDED_FOR"] = "10.0.0.1"
        assert get_client_ip(request) == "10.0.0.1"

    def test_x_forwarded_for_chain(self):
        """nginx appends the real IP to the end of the XFF chain.
        Take the rightmost (last) element — it's set by the trusted proxy."""
        request = self.factory.get("/")
        request.META["HTTP_X_FORWARDED_FOR"] = "10.0.0.1, 172.16.0.1, 192.168.0.1"
        assert get_client_ip(request) == "192.168.0.1"

    def test_x_forwarded_for_spoof_rejected(self):
        """Client tries to spoof the IP via XFF.
        nginx appends the real IP at the end: 'fake, real'.
        The function must return 'real', not 'fake'."""
        request = self.factory.get("/")
        request.META["HTTP_X_FORWARDED_FOR"] = "1.3.3.7, 203.0.113.5"
        assert get_client_ip(request) == "203.0.113.5"

    def test_x_forwarded_for_takes_priority(self):
        request = self.factory.get("/")
        request.META["REMOTE_ADDR"] = "127.0.0.1"
        request.META["HTTP_X_FORWARDED_FOR"] = "203.0.113.5"
        assert get_client_ip(request) == "203.0.113.5"
