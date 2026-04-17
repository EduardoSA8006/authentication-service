"""Integration tests pra POST /auth/logout."""


class TestLogout:
    async def test_happy_path_clears_cookies(self, logged_in_client):
        user, client = logged_in_client
        r = await client.post("/auth/logout")
        assert r.status_code == 200
        # Cookies devem ser limpos (Set-Cookie com Max-Age=0)
        set_cookie = r.headers.get("set-cookie", "")
        assert "session=" in set_cookie.lower()

    async def test_without_session_401(self, client):
        r = await client.post("/auth/logout")
        assert r.status_code == 401

    async def test_csrf_missing_blocks(self, client, make_user):
        await make_user(email="nocsrf@test.com", password="SenhaForte@2026")
        await client.post("/auth/login", json={
            "email": "nocsrf@test.com", "password": "SenhaForte@2026",
        })
        # Sem X-CSRF-Token
        r = await client.post("/auth/logout")
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "CSRF_FAILED"
