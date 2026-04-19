"""Unit + integration tests para app.core.captcha.

Semântica: fail-CLOSED em todos os erros. True apenas se o provider confirmou.
"""
import contextlib
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest_asyncio

from app.core.captcha import verify_captcha
from app.core.config import settings


@pytest_asyncio.fixture
async def turnstile_enabled():
    """Ativa Turnstile com secret válido durante o teste."""
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(settings, "CAPTCHA_ENABLED", True))
        stack.enter_context(patch.object(settings, "CAPTCHA_SECRET", "server-secret"))
        stack.enter_context(patch.object(settings, "CAPTCHA_PROVIDER", "turnstile"))
        yield


def _mock_response(json_data: dict, status_code: int = 200):
    resp = MagicMock(spec=httpx.Response)
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "err", request=MagicMock(), response=resp,
        )
    return resp


class TestVerifyCaptchaGates:
    async def test_disabled_returns_false(self):
        """CAPTCHA_ENABLED=False → nunca há bypass. Caller trata como hard-block."""
        with patch.object(settings, "CAPTCHA_ENABLED", False):
            assert await verify_captcha("any-token", "1.2.3.4") is False

    async def test_empty_token_returns_false(self):
        with patch.object(settings, "CAPTCHA_ENABLED", True), \
             patch.object(settings, "CAPTCHA_SECRET", "server-secret"):
            assert await verify_captcha("", "1.2.3.4") is False

    async def test_empty_secret_returns_false(self):
        """Sem secret configurado, não conseguimos validar — fail-closed."""
        with patch.object(settings, "CAPTCHA_ENABLED", True), \
             patch.object(settings, "CAPTCHA_SECRET", ""):
            assert await verify_captcha("any-token", "1.2.3.4") is False

    async def test_unknown_provider_returns_false(self):
        with patch.object(settings, "CAPTCHA_ENABLED", True), \
             patch.object(settings, "CAPTCHA_SECRET", "secret"), \
             patch.object(settings, "CAPTCHA_PROVIDER", "nonexistent-provider"):
            assert await verify_captcha("token", "1.2.3.4") is False


class TestTurnstileVerify:
    async def test_provider_success_returns_true(self, turnstile_enabled):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mpost:
            mpost.return_value = _mock_response({"success": True})
            assert await verify_captcha("good-token", "1.2.3.4") is True

    async def test_provider_rejects_returns_false(self, turnstile_enabled):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mpost:
            mpost.return_value = _mock_response({
                "success": False,
                "error-codes": ["invalid-input-response"],
            })
            assert await verify_captcha("expired-token", "1.2.3.4") is False

    async def test_http_error_returns_false_fail_closed(self, turnstile_enabled):
        """Provider down (5xx) → False. Não bypassa Layer 2 com provider morto."""
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mpost:
            mpost.return_value = _mock_response({}, status_code=500)
            assert await verify_captcha("token", "1.2.3.4") is False

    async def test_network_error_returns_false_fail_closed(self, turnstile_enabled):
        with patch(
            "httpx.AsyncClient.post",
            new_callable=AsyncMock,
            side_effect=httpx.ConnectError("network down"),
        ):
            assert await verify_captcha("token", "1.2.3.4") is False

    async def test_malformed_json_returns_false(self, turnstile_enabled):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mpost:
            mpost.return_value = _mock_response({})  # missing 'success'
            assert await verify_captcha("token", "1.2.3.4") is False

    async def test_sends_secret_token_ip_to_provider(self, turnstile_enabled):
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mpost:
            mpost.return_value = _mock_response({"success": True})
            await verify_captcha("user-token", "10.0.0.5")

            _, kwargs = mpost.call_args
            data = kwargs["data"]
            assert data["secret"] == "server-secret"
            assert data["response"] == "user-token"
            assert data["remoteip"] == "10.0.0.5"
