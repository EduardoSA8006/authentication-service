"""Integration tests pra RequestSizeLimitMiddleware."""


class TestSizeLimit:
    async def test_oversized_body_rejected(self, client):
        # MAX_REQUEST_SIZE = 10_485_760 bytes
        # Usar Content-Length maior que o limite
        big_body = "x" * (10_485_761)
        r = await client.post(
            "/auth/register",
            content=big_body,
            headers={"Content-Type": "application/json", "Content-Length": str(10_485_761)},
        )
        assert r.status_code == 413
        assert r.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"

    async def test_normal_body_passes(self, client):
        # ~1KB body, deve passar (pode falhar validação JSON, mas não 413)
        r = await client.post("/auth/register", json={
            "name": "Normal User", "email": "n@test.com",
            "password": "SenhaForte@2026", "date_of_birth": "1990-01-01",
        })
        assert r.status_code != 413
