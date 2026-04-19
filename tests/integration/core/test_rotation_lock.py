"""Regression tests para L-2 (lock de rotação concorrente) e N-1
(rotação sequencial a partir de snapshot stale)."""


from unittest.mock import MagicMock

from fastapi import Request

from app.core.redis import get_redis
from app.core.security import (
    _session_key,
    create_session,
    get_session,
    list_user_sessions,
    rotate_session,
)


def _fake_request() -> Request:
    req = MagicMock(spec=Request)
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    req.headers = {"user-agent": "test"}
    return req


class TestRotationLock:
    async def test_rotation_returns_token_when_lock_free(self, _clean_redis):
        token = await create_session("user-123", _fake_request())
        session = await get_session(token)

        new_token = await rotate_session(token, session)
        assert new_token is not None
        assert new_token != token

    async def test_rotation_skipped_when_lock_held(self, _clean_redis):
        """Simula corrida: outra request já tem o lock → rotate retorna None."""
        token = await create_session("user-456", _fake_request())
        session = await get_session(token)

        # Pré-seta o lock key (simula outra request rotacionando agora)
        redis = get_redis()
        lock_key = f"rotate_lock:{_session_key(token)}"
        await redis.set(lock_key, "1", ex=5)

        result = await rotate_session(token, session)
        assert result is None  # rotação foi pulada

    async def test_lock_released_after_success(self, _clean_redis):
        """Lock não persiste após rotação bem-sucedida."""
        token = await create_session("user-789", _fake_request())
        session = await get_session(token)

        await rotate_session(token, session)

        # Lock do token ANTIGO foi liberado
        redis = get_redis()
        lock_key = f"rotate_lock:{_session_key(token)}"
        assert await redis.get(lock_key) is None

    async def test_sequential_stale_rotation_aborts(self, _clean_redis):
        """N-1: duas rotações sequenciais da mesma sessão obsoleta não criam órfão.

        Simula R1 e R2 que carregaram o session ANTES da rotação: R1 rotaciona
        primeiro (sucesso), R2 chega depois com snapshot stale e lock já livre.
        CAS em rotated_at precisa detectar que o estado mudou e abortar,
        senão fica uma sessão órfã válida até SESSION_TTL."""
        user_id = "user-seq"
        token = await create_session(user_id, _fake_request())

        # Ambas "requests" leram o session antes da primeira rotação.
        # Dicts separados para refletir carregamento independente em middleware.
        stale_r1 = await get_session(token)
        stale_r2 = await get_session(token)
        assert stale_r1["rotated_at"] == stale_r2["rotated_at"]

        # R1 rotaciona primeiro (lock livre, CAS passa).
        new_token_1 = await rotate_session(token, stale_r1)
        assert new_token_1 is not None
        assert new_token_1 != token

        # R2 chega depois: lock livre (R1 já liberou), MAS seu snapshot está stale.
        # Sem CAS, R2 criaria new_token_2 e deixaria uma sessão órfã no set.
        # Com CAS, R2 detecta que old_key está em grace e aborta.
        new_token_2 = await rotate_session(token, stale_r2)
        assert new_token_2 is None, "CAS falhou: sessão órfã criada a partir de snapshot stale"

        # Invariante pós-fix: exatamente UMA sessão ativa (a de R1).
        # A antiga virou grace e foi removida do set em rotate_session.
        sessions = await list_user_sessions(user_id)
        assert len(sessions) == 1, f"esperado 1 sessão ativa, encontrei {len(sessions)}"
        assert not sessions[0].get("grace")

        # Token novo de R1 é o único válido. Token antigo ainda existe como grace.
        active = await get_session(new_token_1)
        assert active is not None
        assert not active.get("grace")

        grace = await get_session(token)
        assert grace is not None
        assert grace.get("grace") is True
