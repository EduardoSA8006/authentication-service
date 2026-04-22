"""Integration tests pra RateLimitMiddleware global."""


class TestRateLimitGlobal:
    async def test_health_allowed_normally(self, client):
        for _ in range(10):
            r = await client.get("/health")
            assert r.status_code == 200

    async def test_global_limit_hits(self, client):
        # RATE_LIMIT_REQUESTS=100/window=60s
        # /health é exempt (N-4), então usamos rota arbitrária. 404 é OK — o
        # limiter roda ANTES do routing, conta independentemente do status final.
        responses = []
        for _ in range(101):
            r = await client.get("/_rate_limit_target_nonexistent")
            responses.append(r.status_code)
        assert 429 in responses

    async def test_health_bypasses_rate_limit(self, client):
        """N-4: /health não passa pelo rate limiter. Essencial para probes de
        LB (AWS ALB, k8s liveness, GCP LB) — se o bucket global saturar com
        tráfego legítimo, LB marcaria a instância unhealthy e drenaria o pool.
        """
        # Satura o global limiter via rota não-exempt (101 > RATE_LIMIT_REQUESTS=100)
        for _ in range(101):
            await client.get("/_rate_limit_target_nonexistent")

        # /health permanece 200 mesmo com o bucket estourado
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    async def test_429_carries_cors_headers(self, client):
        """Regression: RateLimit tem de rodar DENTRO do CORS middleware. Se
        CORS não injetasse headers no 429, o browser bloquearia a response
        como 'network error' e o frontend perderia Retry-After e o status."""
        responses = []
        for _ in range(101):
            r = await client.get(
                "/_rate_limit_target_cors",
                headers={"Origin": "http://localhost:3000"},
            )
            responses.append(r)
        blocked = [r for r in responses if r.status_code == 429]
        assert blocked, "nenhum 429 recebido"
        rate_limited = blocked[0]
        assert rate_limited.headers.get("access-control-allow-origin") == (
            "http://localhost:3000"
        )
        assert rate_limited.headers.get("retry-after")

    async def test_rate_limiter_not_invoked_for_health(self, client):
        """Structural: se o limiter explode, /health ainda passa. Prova que
        /health short-circuita antes do sliding_window_incr."""
        from unittest.mock import patch

        async def _boom(*args, **kwargs):
            raise AssertionError("rate limiter invocado para /health")

        with patch("app.core.rate_limit.sliding_window_incr", side_effect=_boom):
            r = await client.get("/health")
        assert r.status_code == 200
