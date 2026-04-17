"""E2E: regression do bug crítico — grace session não pode ter TTL estendido."""


from app.core.config import settings
from app.core.redis import get_redis
from app.core.security import _session_key


class TestGraceSessionTTL:
    async def test_grace_token_ttl_stays_at_60s(
        self, client, make_user, monkeypatch,
    ):
        """Quando sessão é rotacionada, o token antigo vira grace com TTL=60s.
        Se o grace token for usado, o TTL NÃO deve ser estendido (bug da auditoria)."""
        await make_user(email="grace@test.com", password="SenhaForte@2026")

        # Login
        r = await client.post("/auth/login", json={
            "email": "grace@test.com", "password": "SenhaForte@2026",
        })
        old_token = r.cookies["session"]
        csrf = r.cookies["csrf_token"]

        # Força rotação no próximo request
        monkeypatch.setattr(settings, "TOKEN_ROTATION_INTERVAL", 0)

        # Request que causa rotação
        client.headers["X-CSRF-Token"] = csrf
        r2 = await client.get("/auth/me")
        assert r2.status_code == 200
        new_token = r2.cookies.get("session")
        assert new_token and new_token != old_token

        # Token antigo agora é grace, TTL ~60s
        redis = get_redis()
        old_key = _session_key(old_token)
        ttl_before = await redis.ttl(old_key)
        assert 0 < ttl_before <= 60, f"Grace TTL esperado ≤60s, got {ttl_before}"

        # Usar token antigo (grace) — TTL NÃO deve ser estendido
        import httpx
        from httpx import ASGITransport
        from app.main import app

        async with httpx.AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Origin": "http://localhost:3000"},
            cookies={"session": old_token, "csrf_token": csrf},
        ) as old_client:
            await old_client.get("/auth/me")

        # Verifica TTL do grace key após uso — deve continuar ≤60s
        ttl_after = await redis.ttl(old_key)
        assert ttl_after <= 60, (
            f"BUG: grace TTL foi estendido para {ttl_after}s (deveria ser ≤60s)"
        )
