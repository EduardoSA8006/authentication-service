"""E2E: CSRF é HMAC-vinculado à sessão; token de outra sessão não funciona."""
import httpx
from httpx import ASGITransport

from app.main import app


class TestCSRFBinding:
    async def test_csrf_from_other_session_rejected(
        self, client, make_user,
    ):
        await make_user(email="a@test.com", password="SenhaForte@2026")
        await make_user(email="b@test.com", password="SenhaForte@2026")

        # User A login → pega CSRF A
        r_a = await client.post("/auth/login", json={
            "email": "a@test.com", "password": "SenhaForte@2026",
        })
        csrf_a = r_a.cookies["csrf_token"]

        # User B login num client separado
        async with httpx.AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
            headers={"Origin": "http://localhost:3000"},
        ) as client_b:
            r_b = await client_b.post("/auth/login", json={
                "email": "b@test.com", "password": "SenhaForte@2026",
            })
            session_b = r_b.cookies["session"]

            # Tentar usar CSRF de A com sessão de B → deve falhar
            async with httpx.AsyncClient(
                transport=ASGITransport(app=app),
                base_url="http://test",
                headers={
                    "Origin": "http://localhost:3000",
                    "X-CSRF-Token": csrf_a,   # csrf do A
                },
                cookies={"session": session_b},  # sessão de B
            ) as attacker:
                r = await attacker.post("/auth/logout")
                assert r.status_code == 403
                assert r.json()["error"]["code"] == "CSRF_FAILED"
