"""Regression tests para L-2: lock de rotação concorrente."""


from app.core.redis import get_redis
from app.core.security import _session_key, create_session, rotate_session
from fastapi import Request
from unittest.mock import MagicMock


class TestRotationLock:
    async def test_rotation_returns_token_when_lock_free(self, _clean_redis):
        req = MagicMock(spec=Request)
        req.client = MagicMock()
        req.client.host = "127.0.0.1"
        req.headers = {"user-agent": "test"}

        token = await create_session("user-123", req)
        session = {
            "user_id": "user-123",
            "created_at": "2026-01-01T00:00:00+00:00",
            "last_active": "2026-01-01T00:00:00+00:00",
            "rotated_at": "2026-01-01T00:00:00+00:00",
            "ip": "127.0.0.1",
            "user_agent": "test",
        }
        new_token = await rotate_session(token, session)
        assert new_token is not None
        assert new_token != token

    async def test_rotation_skipped_when_lock_held(self, _clean_redis):
        """Simula corrida: outra request já tem o lock → rotate retorna None."""
        req = MagicMock(spec=Request)
        req.client = MagicMock()
        req.client.host = "127.0.0.1"
        req.headers = {"user-agent": "test"}

        token = await create_session("user-456", req)
        session = {
            "user_id": "user-456",
            "created_at": "2026-01-01T00:00:00+00:00",
            "last_active": "2026-01-01T00:00:00+00:00",
            "rotated_at": "2026-01-01T00:00:00+00:00",
            "ip": "127.0.0.1",
            "user_agent": "test",
        }

        # Pré-seta o lock key (simula outra request rotacionando agora)
        redis = get_redis()
        lock_key = f"rotate_lock:{_session_key(token)}"
        await redis.set(lock_key, "1", ex=5)

        result = await rotate_session(token, session)
        assert result is None  # rotação foi pulada

    async def test_lock_released_after_success(self, _clean_redis):
        """Lock não persiste após rotação bem-sucedida."""
        req = MagicMock(spec=Request)
        req.client = MagicMock()
        req.client.host = "127.0.0.1"
        req.headers = {"user-agent": "test"}

        token = await create_session("user-789", req)
        session = {
            "user_id": "user-789",
            "created_at": "2026-01-01T00:00:00+00:00",
            "last_active": "2026-01-01T00:00:00+00:00",
            "rotated_at": "2026-01-01T00:00:00+00:00",
            "ip": "127.0.0.1",
            "user_agent": "test",
        }

        await rotate_session(token, session)

        # Lock do token ANTIGO foi liberado
        redis = get_redis()
        lock_key = f"rotate_lock:{_session_key(token)}"
        assert await redis.get(lock_key) is None
