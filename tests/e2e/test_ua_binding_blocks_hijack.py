"""E2E: UA binding mata sessão se UA muda completamente (session hijack)."""
import httpx
from httpx import ASGITransport

from app.main import app


class TestUABinding:
    async def test_different_browser_killed(self, client, make_user):
        await make_user(email="hijack@test.com", password="SenhaForte@2026")

        # Login com UA Chrome
        r = await client.post(
            "/auth/login",
            json={"email": "hijack@test.com", "password": "SenhaForte@2026"},
            headers={"User-Agent": "Mozilla/5.0 Chrome/130.0"},
        )
        session = r.cookies["session"]

        # "Atacante" usa o cookie com UA totalmente diferente
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            cookies={"session": session},
            headers={
                "Origin": "http://localhost:3000",
                "User-Agent": "CustomBot/1.0",
            },
        ) as attacker:
            r = await attacker.get("/auth/me")
            assert r.status_code == 401  # sessão morta
