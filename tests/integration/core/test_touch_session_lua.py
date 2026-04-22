"""N-24: touch_session Lua mantém max(last_active) sob concorrência.

Testa diretamente o script Lua (via redis.eval) pra evitar que
`touch_session` sobrescreva last_active com `datetime.now()` antes do EVAL
— queremos validar o CAS no servidor, não o Python wrapper.

Dois touches concorrentes da mesma sessão não podem fazer last_active
regredir — senão is_expired pode falsear negativo no idle timeout.
"""
import json

import pytest

from app.core.redis import get_redis
from app.core.security import _LUA_TOUCH, _session_key


def _make_session(last_active: str) -> dict:
    return {
        "user_id": "test-user",
        "created_at": "2026-01-01T00:00:00+00:00",
        "last_active": last_active,
        "rotated_at": "2026-01-01T00:00:00+00:00",
        "ip": "1.2.3.4",
        "user_agent": "Test",
    }


async def _run_touch(key: str, incoming: dict) -> int:
    redis = get_redis()
    result = await redis.eval(  # noqa: S307  (Lua no servidor Redis)
        _LUA_TOUCH, 1, key, json.dumps(incoming), "3600",
    )
    return int(result)


class TestTouchLua:
    @pytest.fixture(autouse=True)
    async def _reset_redis(self):
        redis = get_redis()
        await redis.flushdb()
        yield

    async def test_newer_last_active_wins(self):
        token = "test-token-abc"
        redis = get_redis()
        key = _session_key(token)
        stored = _make_session("2026-04-20T10:00:00+00:00")
        await redis.set(key, json.dumps(stored), ex=3600)

        incoming = _make_session("2026-04-20T11:00:00+00:00")
        assert await _run_touch(key, incoming) == 1

        persisted = json.loads(await redis.get(key))
        assert persisted["last_active"] == "2026-04-20T11:00:00+00:00"

    async def test_stale_last_active_does_not_regress(self):
        """Race: B escreveu com snapshot mais velho após A. Lua mantém
        o max — last_active não regride."""
        token = "test-token-race"
        redis = get_redis()
        key = _session_key(token)
        newer = _make_session("2026-04-20T11:00:00+00:00")
        await redis.set(key, json.dumps(newer), ex=3600)

        stale = _make_session("2026-04-20T10:00:00+00:00")
        assert await _run_touch(key, stale) == 1

        persisted = json.loads(await redis.get(key))
        assert persisted["last_active"] == "2026-04-20T11:00:00+00:00"

    async def test_grace_skipped(self):
        token = "test-token-grace"
        redis = get_redis()
        key = _session_key(token)
        grace_data = _make_session("2026-04-20T10:00:00+00:00")
        grace_data["grace"] = True
        await redis.set(key, json.dumps(grace_data), ex=60)

        incoming = _make_session("2026-04-20T11:00:00+00:00")
        assert await _run_touch(key, incoming) == 0

        persisted = json.loads(await redis.get(key))
        assert persisted.get("grace") is True
        assert persisted["last_active"] == "2026-04-20T10:00:00+00:00"

    async def test_missing_key_noop(self):
        token = "test-token-missing"
        redis = get_redis()
        key = _session_key(token)

        incoming = _make_session("2026-04-20T11:00:00+00:00")
        assert await _run_touch(key, incoming) == 0

        assert await redis.get(key) is None
