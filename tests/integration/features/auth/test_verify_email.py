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

    async def test_token_payload_does_not_contain_email(self, client, mailhog):
        """N-35: verify token no Redis só guarda user_id — se Redis vazar,
        email não vaza junto. Mesmo approach do reset token."""
        import json

        from app.core.redis import get_redis
        from app.features.auth.service import _verify_token_key

        await client.post("/auth/register", json={
            "name": "No Email Token", "email": "noemail@test.com",
            "password": "SenhaForte@2026", "date_of_birth": "1990-01-01",
        })
        token = await mailhog.extract_verification_token()

        raw = await get_redis().get(_verify_token_key(token))
        payload = json.loads(raw)
        assert "user_id" in payload
        assert "email" not in payload
        # Email não aparece em parte alguma do payload
        assert "noemail@test.com" not in raw

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
