"""Healthchecks /livez e /readyz (N-9).

/livez: 200 enquanto processo responde. NÃO toca deps.
/readyz: 200 só se Redis + DB respondem em timeout; 503 caso contrário
         (LB drena sem matar o pod).
/health: alias de /livez (backwards compat).
"""
from unittest.mock import patch


class TestLivez:
    async def test_returns_200(self, client):
        r = await client.get("/livez")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    async def test_does_not_check_redis(self, client):
        """Mesmo com Redis fora, /livez permanece 200 — senão LB restarta
        o pod em incidente de Redis e amplifica a falha."""
        from app.core import redis as redis_mod

        with patch.object(redis_mod, "_redis", None):
            r = await client.get("/livez")
            assert r.status_code == 200


class TestReadyz:
    async def test_healthy_returns_200(self, client):
        r = await client.get("/readyz")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert body["dependencies"]["redis"] == "ok"
        assert body["dependencies"]["database"] == "ok"

    async def test_redis_failure_returns_503(self, client):
        """Redis PING falha → 503 com dependency marcada, sem derrubar o pod."""
        from app.core.redis import get_redis

        real_redis = get_redis()

        async def _boom():
            raise ConnectionError("redis is down")

        with patch.object(real_redis, "ping", side_effect=_boom):
            r = await client.get("/readyz")

        assert r.status_code == 503
        body = r.json()
        assert body["status"] == "degraded"
        assert body["dependencies"]["redis"].startswith("error:")
        assert body["dependencies"]["database"] == "ok"

    async def test_redis_timeout_returns_503(self, client):
        """Redis lento além do timeout curto → 503 (não bloqueia indefinidamente)."""
        import asyncio

        from app.core.redis import get_redis

        real_redis = get_redis()

        async def _hang():
            await asyncio.sleep(10)
            return True

        with patch.object(real_redis, "ping", side_effect=_hang):
            r = await client.get("/readyz")

        assert r.status_code == 503
        assert r.json()["dependencies"]["redis"].startswith("error:")


class TestHealthAlias:
    async def test_health_still_returns_200(self, client):
        """Compat: /health continua ok enquanto ops migra LB config."""
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}


class TestHealthchecksRateLimitExempt:
    async def test_livez_not_rate_limited(self, client):
        """Se o global bucket saturar, /livez/readyz não podem cair em 429 —
        LB marcaria target unhealthy e drenaria a instância inteira."""
        # Satura o bucket global via path não-exempt
        for _ in range(101):
            await client.get("/_rl_target")

        r = await client.get("/livez")
        assert r.status_code == 200

    async def test_readyz_not_rate_limited(self, client):
        for _ in range(101):
            await client.get("/_rl_target")

        r = await client.get("/readyz")
        assert r.status_code == 200
