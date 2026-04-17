"""E2E: progressive lockout após 10 falhas de login."""


class TestBruteForceLockout:
    async def test_lockout_blocks_even_correct_password(self, client, make_user):
        await make_user(email="victim@test.com", password="SenhaForte@2026")

        # 10 tentativas erradas
        for i in range(10):
            r = await client.post("/auth/login", json={
                "email": "victim@test.com", "password": f"wrong-pwd-{i}@Q9",
            })
            # Algumas vão bater rate limit IP antes do lockout; ambos retornam 429/401
            assert r.status_code in (401, 429)

        # 11ª com senha CORRETA — deve estar bloqueada
        r = await client.post("/auth/login", json={
            "email": "victim@test.com", "password": "SenhaForte@2026",
        })
        assert r.status_code == 429
        assert "Retry-After" in r.headers
