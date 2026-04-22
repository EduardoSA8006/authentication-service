"""Integration tests pra CSRFMiddleware."""


class TestCSRF:
    async def test_get_skipped_without_csrf(self, client):
        r = await client.get("/health")
        assert r.status_code == 200

    async def test_unauthenticated_post_needs_origin(self, client):
        client.headers.pop("Origin", None)
        r = await client.post(
            "/auth/register",
            json={"name": "X", "email": "y@z.com", "password": "Senha@123", "date_of_birth": "1990-01-01"},
            headers={"Referer": ""},
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "ORIGIN_MISSING"

    async def test_unauthenticated_post_wrong_origin(self, client):
        r = await client.post(
            "/auth/register",
            json={"name": "X Y", "email": "y@z.com", "password": "Senha@1234!", "date_of_birth": "1990-01-01"},
            headers={"Origin": "http://evil.com"},
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "ORIGIN_REJECTED"

    async def test_authenticated_post_needs_csrf_header(self, client, make_user):
        await make_user(email="c@test.com", password="SenhaForte@2026")
        await client.post("/auth/login", json={
            "email": "c@test.com", "password": "SenhaForte@2026",
        })
        # Sem X-CSRF-Token
        r = await client.post("/auth/logout")
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "CSRF_FAILED"

    async def test_authenticated_post_with_valid_csrf_passes(self, logged_in_client):
        user, client = logged_in_client
        r = await client.post("/auth/logout")
        assert r.status_code == 200

    async def test_authenticated_post_with_wrong_csrf_rejected(self, client, make_user):
        await make_user(email="wc@test.com", password="SenhaForte@2026")
        await client.post("/auth/login", json={
            "email": "wc@test.com", "password": "SenhaForte@2026",
        })
        client.headers["X-CSRF-Token"] = "wrong-csrf-token"
        r = await client.post("/auth/logout")
        assert r.status_code == 403

    async def test_referer_is_not_accepted_as_origin_fallback(self, client):
        """Referer não é gate — só Origin. Defensivo contra edge-cases de
        urlparse (http://evil#@legit, http:///\\\\legit) e cenários onde
        atacante consegue suprimir Origin mas forjar Referer."""
        client.headers.pop("Origin", None)
        r = await client.post(
            "/auth/register",
            json={"name": "Ref Erer", "email": "ref@test.com", "password": "SenhaForte@2026", "date_of_birth": "1990-01-01"},
            headers={"Referer": "http://localhost:3000/signup"},
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "ORIGIN_MISSING"

    async def test_csrf_failure_logs_warning(self, client, make_user, caplog):
        """N-19: falha CSRF deve logar WARNING com method/path/ip pra alertas."""
        import logging
        caplog.set_level(logging.WARNING, logger="app.core.middleware")

        await make_user(email="csrflog@test.com", password="SenhaForte@2026")
        await client.post("/auth/login", json={
            "email": "csrflog@test.com", "password": "SenhaForte@2026",
        })
        client.headers["X-CSRF-Token"] = "wrong"

        r = await client.post("/auth/logout")
        assert r.status_code == 403

        assert any(
            "CSRF gate failure: CSRF_FAILED" in rec.message
            and "path=/auth/logout" in rec.message
            for rec in caplog.records
        )

    async def test_origin_missing_logs_warning(self, client, caplog):
        import logging
        caplog.set_level(logging.WARNING, logger="app.core.middleware")

        client.headers.pop("Origin", None)
        r = await client.post(
            "/auth/register",
            json={
                "name": "X", "email": "y@z.com",
                "password": "Senha@123", "date_of_birth": "1990-01-01",
            },
        )
        assert r.status_code == 403
        assert any(
            "ORIGIN_MISSING" in rec.message for rec in caplog.records
        )

    async def test_origin_rejected_even_with_matching_referer(self, client):
        """Origin errado + Referer aliado: Origin vence, rejeita."""
        r = await client.post(
            "/auth/register",
            json={"name": "X Y", "email": "mix@test.com", "password": "Senha@1234!", "date_of_birth": "1990-01-01"},
            headers={
                "Origin": "http://evil.com",
                "Referer": "http://localhost:3000/signup",
            },
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "ORIGIN_REJECTED"
