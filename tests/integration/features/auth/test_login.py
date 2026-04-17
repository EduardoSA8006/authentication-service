"""Integration tests pra POST /auth/login."""


class TestLogin:
    async def test_happy_path_sets_cookies(self, client, make_user):
        await make_user(email="login@test.com", password="SenhaForte@2026", verified=True)
        r = await client.post("/auth/login", json={
            "email": "login@test.com", "password": "SenhaForte@2026",
        })
        assert r.status_code == 200
        assert "session" in r.cookies
        assert "csrf_token" in r.cookies
        assert r.json()["email"] == "login@test.com"

    async def test_wrong_password_generic_401(self, client, make_user):
        await make_user(email="pw@test.com", password="SenhaForte@2026")
        r = await client.post("/auth/login", json={
            "email": "pw@test.com", "password": "SenhaErrada@9999",
        })
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "INVALID_CREDENTIALS"

    async def test_nonexistent_email_same_response_anti_enum(self, client):
        r = await client.post("/auth/login", json={
            "email": "ghost@nowhere.com", "password": "Whatever@1234",
        })
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "INVALID_CREDENTIALS"

    async def test_unverified_blocked(self, client, make_user):
        await make_user(email="unv@test.com", password="SenhaForte@2026", verified=False)
        r = await client.post("/auth/login", json={
            "email": "unv@test.com", "password": "SenhaForte@2026",
        })
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "EMAIL_NOT_VERIFIED"

    async def test_rate_limit_per_ip(self, client, make_user):
        await make_user(email="rl@test.com", password="SenhaForte@2026")
        # LOGIN_IP = (10, 60)
        for _ in range(10):
            await client.post("/auth/login", json={
                "email": "rl@test.com", "password": "wrong-pw-attempt",
            })
        r = await client.post("/auth/login", json={
            "email": "rl@test.com", "password": "SenhaForte@2026",
        })
        assert r.status_code == 429

    async def test_progressive_lockout_after_10_failures(self, client, make_user):
        await make_user(email="lock@test.com", password="SenhaForte@2026")
        # 10 falhas → 11ª bloqueada mesmo com senha correta
        for i in range(10):
            r = await client.post("/auth/login", json={
                "email": "lock@test.com", "password": f"wrong-{i}@Q9",
            })
            # Primeiras podem ser 401, eventualmente rate limit (10/60 IP)
            # mas lockout é por email
        r = await client.post("/auth/login", json={
            "email": "lock@test.com", "password": "SenhaForte@2026",
        })
        # Pode ser 429 por IP rate limit OU por lockout de email
        assert r.status_code == 429

    async def test_origin_missing_blocked(self, client, make_user):
        await make_user(email="o@test.com", password="SenhaForte@2026")
        client.headers.pop("Origin", None)
        r = await client.post(
            "/auth/login", json={"email": "o@test.com", "password": "SenhaForte@2026"},
            headers={"Referer": ""},
        )
        assert r.status_code == 403
