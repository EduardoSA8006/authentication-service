"""N-12: retry com backoff para emails críticos (register worker)."""
from unittest.mock import AsyncMock, patch

from app.features.auth.service import _send_email_with_retry


class TestSendEmailRetry:
    async def test_success_on_first_attempt(self):
        called = 0

        async def _send():
            nonlocal called
            called += 1

        ok = await _send_email_with_retry(
            lambda: _send(), label="test_first_try",
        )
        assert ok is True
        assert called == 1

    async def test_success_on_second_attempt(self):
        """Flap transiente: primeira falha, segunda sucesso."""
        calls = 0

        async def _flap():
            nonlocal calls
            calls += 1
            if calls == 1:
                raise ConnectionError("smtp timeout")

        # Encurta backoff no teste pra não esperar 1s real
        with patch("app.features.auth.service.asyncio.sleep", AsyncMock()):
            ok = await _send_email_with_retry(
                lambda: _flap(), label="test_flap",
            )
        assert ok is True
        assert calls == 2

    async def test_all_attempts_fail_returns_false(self):
        """Todas as 3 tentativas falham → False (não levanta). Caller decide
        como escalar — _register_worker loga com 'user precisa resend'."""
        calls = 0

        async def _always_fail():
            nonlocal calls
            calls += 1
            raise ConnectionError("persistent smtp failure")

        with patch("app.features.auth.service.asyncio.sleep", AsyncMock()):
            ok = await _send_email_with_retry(
                lambda: _always_fail(), label="test_persistent_fail",
            )
        assert ok is False
        assert calls == 3

    async def test_exponential_backoff(self):
        """Waits entre tentativas crescem: 1s, 2s (base * 2^(attempt-1))."""
        calls = 0

        async def _always_fail():
            nonlocal calls
            calls += 1
            raise RuntimeError("nope")

        sleep_calls: list[float] = []

        async def _track_sleep(seconds: float):
            sleep_calls.append(seconds)

        with patch(
            "app.features.auth.service.asyncio.sleep",
            side_effect=_track_sleep,
        ):
            await _send_email_with_retry(
                lambda: _always_fail(), label="test_backoff",
            )

        # 3 attempts = 2 sleeps (entre attempt 1→2 e 2→3)
        assert sleep_calls == [1.0, 2.0]
