"""Integration tests pra RateLimitMiddleware global."""


class TestRateLimitGlobal:
    async def test_health_allowed_normally(self, client):
        for _ in range(10):
            r = await client.get("/health")
            assert r.status_code == 200

    async def test_global_limit_hits(self, client):
        # RATE_LIMIT_REQUESTS=100/window=60s
        # Fazer 101 requests rápidas — última 429
        responses = []
        for _ in range(101):
            r = await client.get("/health")
            responses.append(r.status_code)
        # Alguma no final deve ser 429
        assert 429 in responses
