"""E2E: register → email → verify → login → me → logout."""


class TestFullRegisterFlow:
    async def test_complete_flow(self, client, mailhog):
        # 1. Register (fire-and-forget: 202 imediato)
        r = await client.post("/auth/register", json={
            "name": "João Silva",
            "email": "e2e@test.com",
            "password": "SenhaForte@2026",
            "date_of_birth": "1990-01-01",
        })
        assert r.status_code == 202

        # 2. Email chega com token (mailhog.extract_verification_token faz polling,
        # aguarda worker terminar INSERT + SMTP)
        token = await mailhog.extract_verification_token()
        assert len(token) > 20

        # 3. Verify-email
        r = await client.post("/auth/verify-email", json={"token": token})
        assert r.status_code == 200

        # 4. Login
        r = await client.post("/auth/login", json={
            "email": "e2e@test.com", "password": "SenhaForte@2026",
        })
        assert r.status_code == 200
        assert r.cookies.get("session")
        csrf = r.cookies["csrf_token"]

        # 5. /me
        client.headers["X-CSRF-Token"] = csrf
        r = await client.get("/auth/me")
        assert r.status_code == 200
        assert r.json()["email"] == "e2e@test.com"
        assert r.json()["is_verified"] is True

        # 6. Logout
        r = await client.post("/auth/logout")
        assert r.status_code == 200

        # 7. /me sem sessão falha
        r = await client.get("/auth/me")
        assert r.status_code == 401
