"""Integration tests pra SessionMiddleware."""



class TestSession:
    async def test_ua_change_kills_session(self, client, make_user):
        await make_user(email="ua@test.com", password="SenhaForte@2026")
        await client.post("/auth/login", json={
            "email": "ua@test.com", "password": "SenhaForte@2026",
        })
        # Mudar UA completamente
        client.headers["User-Agent"] = "TotallyDifferentBrowser/99.9"
        r = await client.get("/auth/me")
        assert r.status_code == 401

    async def test_minor_ua_version_change_keeps_session(self, client, make_user):
        """Regression: _stable_ua strip versões; update de browser não mata sessão."""
        await make_user(email="ua2@test.com", password="SenhaForte@2026")
        await client.post(
            "/auth/login",
            json={"email": "ua2@test.com", "password": "SenhaForte@2026"},
            headers={"User-Agent": "Mozilla/5.0 Chrome/130.0.6723.58"},
        )
        # Simula update de browser — mesmo UA base
        client.headers["User-Agent"] = "Mozilla/5.0 Chrome/131.0.6784.12"
        r = await client.get("/auth/me")
        assert r.status_code == 200

    async def test_no_session_cookie_no_state(self, client):
        # /health não requer sessão; só valida que middleware não explode
        r = await client.get("/health")
        assert r.status_code == 200
