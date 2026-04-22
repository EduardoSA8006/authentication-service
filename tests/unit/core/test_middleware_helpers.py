"""Unit tests para helpers de middleware."""
from unittest.mock import MagicMock

from app.core.middleware import get_client_ip
from app.core.security import stable_ua


class TestClientIP:
    def _make_request(self, peer: str, headers: dict | None = None):
        r = MagicMock()
        r.client = MagicMock()
        r.client.host = peer
        r.headers = headers or {}
        return r

    def test_returns_peer_ip_when_no_proxy(self):
        req = self._make_request("1.2.3.4")
        assert get_client_ip(req) == "1.2.3.4"

    def test_uses_xff_single_ip_when_peer_is_trusted_proxy(self):
        req = self._make_request("127.0.0.1", {"x-forwarded-for": "5.6.7.8"})
        assert get_client_ip(req) == "5.6.7.8"

    def test_picks_rightmost_nontrusted_in_xff_chain(self):
        """Regression: evita spoofing via XFF.
        Com nginx proxy_add_x_forwarded_for, atacante injeta valor à esquerda
        e IP real é anexado à direita. Pegar [0] deixaria atacante controlar o IP."""
        req = self._make_request(
            "127.0.0.1",
            {"x-forwarded-for": "1.2.3.4, 9.10.11.12"},
        )
        # 9.10.11.12 é o rightmost não-confiável → IP real
        assert get_client_ip(req) == "9.10.11.12"

    def test_skips_trusted_proxies_in_chain(self):
        req = self._make_request(
            "127.0.0.1",
            {"x-forwarded-for": "5.6.7.8, 127.0.0.1"},
        )
        # 127.0.0.1 (rightmost) é proxy confiável → vai pra próximo (5.6.7.8)
        assert get_client_ip(req) == "5.6.7.8"

    def test_ignores_xff_from_non_trusted_peer(self):
        req = self._make_request("1.2.3.4", {"x-forwarded-for": "99.99.99.99"})
        # Peer não é proxy confiável → XFF ignorado
        assert get_client_ip(req) == "1.2.3.4"

    def test_falls_back_to_real_ip(self):
        req = self._make_request("127.0.0.1", {"x-real-ip": "8.8.8.8"})
        assert get_client_ip(req) == "8.8.8.8"

    def test_unknown_when_no_client(self):
        r = MagicMock()
        r.client = None
        r.headers = {}
        assert get_client_ip(r) == "unknown"

    def test_rejects_malformed_xff_value(self):
        """Atacante atrás de proxy confiável injeta lixo no XFF — resultado
        não pode poluir keys de Redis, logs ou templates de email."""
        for bad in ("../../../etc/passwd", "A" * 10000, "💩", "not-an-ip"):
            req = self._make_request("127.0.0.1", {"x-forwarded-for": bad})
            assert get_client_ip(req) == "invalid"

    def test_rejects_malformed_peer(self):
        req = self._make_request("not-an-ip")
        assert get_client_ip(req) == "invalid"

    def test_canonicalizes_ipv4(self):
        """127.0.0.001 e 127.0.0.1 não podem virar chaves Redis distintas."""
        req = self._make_request("1.2.3.4", {})
        # Sanidade: IP válido passa intacto
        assert get_client_ip(req) == "1.2.3.4"

    def test_skips_malformed_entry_in_xff_chain(self):
        """XFF com entrada inválida no meio: fallback para próxima entrada válida."""
        req = self._make_request(
            "127.0.0.1",
            {"x-forwarded-for": "5.6.7.8, garbage"},
        )
        # "garbage" (rightmost) descartado → 5.6.7.8
        assert get_client_ip(req) == "5.6.7.8"


class TestStableUA:
    def test_strips_chrome_version(self):
        ua1 = "Mozilla/5.0 Chrome/130.0.6723.58 Safari/537.36"
        ua2 = "Mozilla/5.0 Chrome/131.0.6784.12 Safari/537.36"
        assert stable_ua(ua1) == stable_ua(ua2)

    def test_preserves_browser_identity(self):
        chrome = stable_ua("Mozilla/5.0 Chrome/130.0 Safari/537.36")
        firefox = stable_ua("Mozilla/5.0 Firefox/130.0")
        assert chrome != firefox

    def test_handles_empty(self):
        assert stable_ua("") == ""

    def test_strips_multiple_versions(self):
        ua = "X/1.0 Y/2.0.3 Z/4.5"
        stable = stable_ua(ua)
        assert "1.0" not in stable
        assert "2.0" not in stable
        assert "4.5" not in stable
