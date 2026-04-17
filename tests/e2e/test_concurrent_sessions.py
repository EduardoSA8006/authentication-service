"""E2E: logout-all mata todas as sessões do usuário."""
import httpx
from httpx import ASGITransport

from app.main import app


class TestConcurrentSessions:
    async def test_logout_all_kills_both_devices(self, client, make_user):
        await make_user(email="multi@test.com", password="SenhaForte@2026")

        # Device A
        r_a = await client.post("/auth/login", json={
            "email": "multi@test.com", "password": "SenhaForte@2026",
        })
        csrf_a = r_a.cookies["csrf_token"]

        # Device B
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Origin": "http://localhost:3000"},
        ) as device_b:
            await device_b.post("/auth/login", json={
                "email": "multi@test.com", "password": "SenhaForte@2026",
            })

            # Device A faz logout-all
            client.headers["X-CSRF-Token"] = csrf_a
            r = await client.post("/auth/logout-all")
            assert r.status_code == 200

            # Device A morto
            r = await client.get("/auth/me")
            assert r.status_code == 401

            # Device B também morto
            r = await device_b.get("/auth/me")
            assert r.status_code == 401
