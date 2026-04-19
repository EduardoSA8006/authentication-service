"""N-7: touch_session é no-op quando sessão é grace.

Dois gates testados:
1. In-memory: caller passa dict com grace=True → short-circuit sem Redis call.
2. Lua CAS: Redis tem grace=True mas dict in-memory está stale → Lua aborta o SET.
   Simula o TOCTOU entre get_session e touch_session sob rotação concorrente.
"""
import json
from unittest.mock import MagicMock

from fastapi import Request

from app.core.redis import get_redis
from app.core.security import (
    _session_key,
    create_session,
    get_session,
    touch_session,
)


def _fake_request():
    req = MagicMock(spec=Request)
    req.client = MagicMock()
    req.client.host = "127.0.0.1"
    req.headers = {"user-agent": "test"}
    return req


class TestTouchSessionInMemoryGuard:
    async def test_grace_dict_is_noop(self, _clean_redis):
        """Caller com dict grace → nem chega no Redis (short-circuit)."""
        token = await create_session("user-grace", _fake_request())
        redis = get_redis()
        key = _session_key(token)

        session = await get_session(token)
        grace_data = {**session, "grace": True}
        # Força estado grace + TTL curto em Redis também
        await redis.set(key, json.dumps(grace_data), ex=60)

        ttl_before = await redis.ttl(key)
        assert 0 < ttl_before <= 60

        await touch_session(token, grace_data)

        ttl_after = await redis.ttl(key)
        assert ttl_after <= 60, f"TTL estendido: {ttl_after}s"
        raw = await redis.get(key)
        assert json.loads(raw).get("grace") is True


class TestTouchSessionLuaCAS:
    async def test_stale_dict_does_not_overwrite_grace_in_redis(self, _clean_redis):
        """TOCTOU simulation: caller tem dict não-grace (stale), Redis tem grace.
        Lua script deve detectar grace em Redis e abortar o SET."""
        token = await create_session("user-race", _fake_request())
        redis = get_redis()
        key = _session_key(token)

        # Snapshot do caller ANTES da rotação (não-grace)
        stale_session = await get_session(token)
        assert not stale_session.get("grace")

        # Simula rotação concorrente: Redis vira grace com TTL 60s
        grace_data = {**stale_session, "grace": True}
        await redis.set(key, json.dumps(grace_data), ex=60)

        ttl_before = await redis.ttl(key)
        assert 0 < ttl_before <= 60

        # Caller chama touch_session com dict STALE (não-grace)
        # In-memory check passa (stale_session.grace=False); Lua deve parar aqui
        await touch_session(token, stale_session)

        # TTL preservado (não estendido pra SESSION_TTL)
        ttl_after = await redis.ttl(key)
        assert ttl_after <= 60, (
            f"Lua CAS falhou: TTL estendido de {ttl_before}s pra {ttl_after}s"
        )

        # Dados em Redis continuam grace
        raw = await redis.get(key)
        assert json.loads(raw).get("grace") is True

    async def test_deleted_key_is_noop(self, _clean_redis):
        """Key deletada (sessão logout) + caller stale → Lua retorna sem criar."""
        token = await create_session("user-gone", _fake_request())
        redis = get_redis()
        key = _session_key(token)

        stale_session = await get_session(token)
        await redis.delete(key)

        await touch_session(token, stale_session)

        # Lua não re-cria a key
        assert await redis.exists(key) == 0


class TestTouchSessionNormalFlow:
    async def test_non_grace_touches_normally(self, _clean_redis):
        """Regression: fluxo normal (não-grace em caller + Redis) → touch funciona."""
        token = await create_session("user-normal", _fake_request())
        redis = get_redis()
        key = _session_key(token)

        # TTL curto pra detectar o refresh
        await redis.expire(key, 100)
        ttl_before = await redis.ttl(key)
        assert 0 < ttl_before <= 100

        session = await get_session(token)
        await touch_session(token, session)

        ttl_after = await redis.ttl(key)
        assert ttl_after > ttl_before, (
            f"TTL não foi estendido: before={ttl_before}s after={ttl_after}s"
        )

    async def test_last_active_is_updated(self, _clean_redis):
        """touch_session atualiza last_active em Redis."""
        token = await create_session("user-la", _fake_request())
        redis = get_redis()
        key = _session_key(token)

        session = await get_session(token)
        original_la = session["last_active"]

        # Pequeno delay + mutação in-memory (touch_session faz isso internamente)
        import asyncio
        await asyncio.sleep(0.01)
        await touch_session(token, session)

        raw = await redis.get(key)
        updated = json.loads(raw)
        assert updated["last_active"] > original_la
