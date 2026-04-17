"""Unit tests para helpers de middleware."""
from unittest.mock import MagicMock

from app.core.middleware import _get_client_ip, _stable_ua


class TestClientIP:
    def _make_request(self, peer: str, headers: dict | None = None):
        r = MagicMock()
        r.client = MagicMock()
        r.client.host = peer
        r.headers = headers or {}
        return r

    def test_returns_peer_ip_when_no_proxy(self):
        req = self._make_request("1.2.3.4")
        assert _get_client_ip(req) == "1.2.3.4"

    def test_uses_xff_when_peer_is_trusted_proxy(self):
        req = self._make_request("127.0.0.1", {"x-forwarded-for": "5.6.7.8"})
        assert _get_client_ip(req) == "5.6.7.8"

    def test_uses_first_ip_in_xff_chain(self):
        req = self._make_request(
            "127.0.0.1",
            {"x-forwarded-for": "5.6.7.8, 9.10.11.12"},
        )
        assert _get_client_ip(req) == "5.6.7.8"

    def test_ignores_xff_from_non_trusted_peer(self):
        req = self._make_request("1.2.3.4", {"x-forwarded-for": "99.99.99.99"})
        # Peer não é proxy confiável → XFF ignorado
        assert _get_client_ip(req) == "1.2.3.4"

    def test_falls_back_to_real_ip(self):
        req = self._make_request("127.0.0.1", {"x-real-ip": "8.8.8.8"})
        assert _get_client_ip(req) == "8.8.8.8"

    def test_unknown_when_no_client(self):
        r = MagicMock()
        r.client = None
        r.headers = {}
        assert _get_client_ip(r) == "unknown"


class TestStableUA:
    def test_strips_chrome_version(self):
        ua1 = "Mozilla/5.0 Chrome/130.0.6723.58 Safari/537.36"
        ua2 = "Mozilla/5.0 Chrome/131.0.6784.12 Safari/537.36"
        assert _stable_ua(ua1) == _stable_ua(ua2)

    def test_preserves_browser_identity(self):
        chrome = _stable_ua("Mozilla/5.0 Chrome/130.0 Safari/537.36")
        firefox = _stable_ua("Mozilla/5.0 Firefox/130.0")
        assert chrome != firefox

    def test_handles_empty(self):
        assert _stable_ua("") == ""

    def test_strips_multiple_versions(self):
        ua = "X/1.0 Y/2.0.3 Z/4.5"
        stable = _stable_ua(ua)
        assert "1.0" not in stable
        assert "2.0" not in stable
        assert "4.5" not in stable
