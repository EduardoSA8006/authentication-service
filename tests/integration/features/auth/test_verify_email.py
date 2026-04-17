"""Integration tests pra POST /auth/verify-email."""


class TestVerifyEmail:
    async def test_valid_token_verifies(self, client, mailhog):
        # Registra pra criar token
        await client.post("/auth/register", json={
            "name": "Verif User", "email": "verif@test.com",
            "password": "SenhaForte@2026", "date_of_birth": "1990-01-01",
        })
        token = await mailhog.extract_verification_token()

        r = await client.post("/auth/verify-email", json={"token": token})
        assert r.status_code == 200
        assert "sucesso" in r.json()["message"]

    async def test_invalid_token_400(self, client):
        r = await client.post("/auth/verify-email", json={"token": "invalid-token-xyz"})
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "INVALID_VERIFICATION_TOKEN"

    async def test_token_cannot_be_used_twice(self, client, mailhog):
        """Regression test: getdel atômico."""
        await client.post("/auth/register", json={
            "name": "Twice User", "email": "twice@test.com",
            "password": "SenhaForte@2026", "date_of_birth": "1990-01-01",
        })
        token = await mailhog.extract_verification_token()

        r1 = await client.post("/auth/verify-email", json={"token": token})
        assert r1.status_code == 200

        r2 = await client.post("/auth/verify-email", json={"token": token})
        assert r2.status_code == 400
