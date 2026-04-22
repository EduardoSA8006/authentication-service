"""Integration tests pra SessionMiddleware."""


_CHROME_WINDOWS = "Mozilla/5.0 (Windows NT 10.0) Chrome/130.0.6723.58 Safari/537.36"
_CHROME_WINDOWS_NEWER = (
    "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0.6784.12 Safari/537.36"
)
_FIREFOX_LINUX = "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Firefox/130.0"


class TestSession:
    async def test_ua_change_kills_session(self, client, make_user):
        """Mudança de (browser, OS family) → sessão morre.
        Chrome/Windows → Firefox/Linux: par diferente, cookie reuso bloqueado."""
        await make_user(email="ua@test.com", password="SenhaForte@2026")
        await client.post(
            "/auth/login",
            json={"email": "ua@test.com", "password": "SenhaForte@2026"},
            headers={"User-Agent": _CHROME_WINDOWS},
        )
        client.headers["User-Agent"] = _FIREFOX_LINUX
        r = await client.get("/auth/me")
        assert r.status_code == 401

    async def test_minor_ua_version_change_keeps_session(self, client, make_user):
        """Chrome auto-update (130 → 131) mantém sessão — binding via
        _ua_summary ignora versão, só observa (browser, OS family)."""
        await make_user(email="ua2@test.com", password="SenhaForte@2026")
        await client.post(
            "/auth/login",
            json={"email": "ua2@test.com", "password": "SenhaForte@2026"},
            headers={"User-Agent": _CHROME_WINDOWS},
        )
        client.headers["User-Agent"] = _CHROME_WINDOWS_NEWER
        r = await client.get("/auth/me")
        assert r.status_code == 200

    async def test_no_session_cookie_no_state(self, client):
        # /health não requer sessão; só valida que middleware não explode
        r = await client.get("/health")
        assert r.status_code == 200

    async def test_corrupt_session_does_not_500(self, client, make_user):
        """Sessão com JSON parcial (sem created_at) não pode virar 500.
        is_expired dispara KeyError; middleware deve capturar, invalidar, seguir."""
        import json

        from app.core.redis import get_redis
        from app.core.security import _session_key

        await make_user(email="corrupt@test.com", password="SenhaForte@2026")
        await client.post("/auth/login", json={
            "email": "corrupt@test.com", "password": "SenhaForte@2026",
        })

        token = client.cookies.get("session")
        # Sobrescreve o session em Redis com JSON corrupto (sem created_at)
        corrupt = {"user_id": "x", "user_agent": "Test"}
        await get_redis().set(_session_key(token), json.dumps(corrupt), ex=3600)

        # Request pós-corruption: não 500, e sessão foi invalidada (401 no
        # endpoint autenticado, não 200/500).
        r = await client.get("/auth/me")
        assert r.status_code == 401
