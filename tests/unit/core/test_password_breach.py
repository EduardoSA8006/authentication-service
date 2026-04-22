"""Unit tests pra HaveIBeenPwned k-anonymity check."""
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch


from app.core.config import settings
from app.core.password_breach import is_password_breached


def _mock_response(text: str):
    r = MagicMock()
    r.text = text
    r.raise_for_status = MagicMock()
    return r


class TestHIBPCheck:
    async def test_disabled_returns_false(self):
        with patch.object(settings, "HIBP_ENABLED", False):
            assert await is_password_breached("password") is False

    async def test_password_in_breach_returns_true(self):
        """Mock httpx: retorna resposta com hash suffix da senha."""
        sha1 = hashlib.sha1(b"pwned-pass", usedforsecurity=False).hexdigest().upper()
        suffix = sha1[5:]
        fake_body = f"ABCDE:1\r\n{suffix}:42\r\nFFFFF:3"

        with patch.object(settings, "HIBP_ENABLED", True), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mget:
            mget.return_value = _mock_response(fake_body)
            assert await is_password_breached("pwned-pass") is True

    async def test_password_not_in_breach_returns_false(self):
        sha1 = hashlib.sha1(b"safe-pass", usedforsecurity=False).hexdigest().upper()
        # Retorna hashes DIFERENTES — senha não é match
        fake_body = "AAAAA:1\r\nBBBBB:2\r\nCCCCC:3"
        # Garantir que suffix de safe-pass NÃO aparece
        assert sha1[5:] not in fake_body

        with patch.object(settings, "HIBP_ENABLED", True), \
             patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mget:
            mget.return_value = _mock_response(fake_body)
            assert await is_password_breached("safe-pass") is False

    async def test_network_error_fails_open(self):
        """Timeout / connection error → False (não bloqueia registration)."""
        with patch.object(settings, "HIBP_ENABLED", True), \
             patch(
                 "httpx.AsyncClient.get",
                 new_callable=AsyncMock,
                 side_effect=Exception("Connection refused"),
             ):
            assert await is_password_breached("any") is False

    async def test_uses_sha1_prefix_only(self):
        """Privacy: só primeiros 5 chars do SHA-1 são enviados."""
        sha1 = hashlib.sha1(b"my-secret", usedforsecurity=False).hexdigest().upper()

        captured_url = []

        async def mock_get(self, url, **kwargs):
            captured_url.append(url)
            return _mock_response("")

        with patch.object(settings, "HIBP_ENABLED", True), \
             patch("httpx.AsyncClient.get", mock_get):
            await is_password_breached("my-secret")

        # URL contém só o prefixo (5 chars), nunca o hash completo
        assert len(captured_url) == 1
        assert sha1[:5] in captured_url[0]
        assert sha1 not in captured_url[0]
        assert sha1[5:] not in captured_url[0]
