"""Regression tests para C-1: XFF spoofing bypass do rate limiter."""
from unittest.mock import MagicMock

from app.core.middleware import get_client_ip


class TestXFFSpoofingRegression:
    def _req(self, peer, xff):
        r = MagicMock()
        r.client = MagicMock()
        r.client.host = peer
        r.headers = {"x-forwarded-for": xff}
        return r

    def test_attacker_leftmost_spoof_is_ignored(self):
        """Cenário: atacante manda XFF='evil.ip', nginx anexa '<real>'.
        Resultado final: 'evil.ip, <real>'. Picking leftmost seria o bypass."""
        r = self._req("127.0.0.1", "1.2.3.4, 10.20.30.40")
        assert get_client_ip(r) == "10.20.30.40"

    def test_deeply_nested_proxies_still_find_real(self):
        """Cenário: request passa por LB → CDN → nginx. XFF tem 3 hops.
        Só último é o real."""
        r = self._req("127.0.0.1", "spoofed1, spoofed2, real.client.ip")
        assert get_client_ip(r) == "real.client.ip"

    def test_multiple_trusted_proxies_skipped(self):
        """Cadeia de trusted proxies à direita → pega o primeiro não-confiável."""
        r = self._req("127.0.0.1", "real.ip, 127.0.0.1, ::1")
        # ::1 rightmost trusted → 127.0.0.1 trusted → real.ip returned
        assert get_client_ip(r) == "real.ip"

    def test_all_trusted_returns_peer(self):
        r = self._req("127.0.0.1", "127.0.0.1, ::1")
        assert get_client_ip(r) == "127.0.0.1"
