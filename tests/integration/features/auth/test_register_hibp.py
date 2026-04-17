"""Integration test: registro rejeita senha em breach HIBP."""
from unittest.mock import patch


class TestRegisterRejectsBreachedPassword:
    async def test_breached_password_returns_400(self, client):
        with patch("app.features.auth.service.is_password_breached", return_value=True):
            r = await client.post("/auth/register", json={
                "name": "Victim User",
                "email": "breached@test.com",
                "password": "SenhaForte@2026",
                "date_of_birth": "1990-01-01",
            })
            assert r.status_code == 400
            assert r.json()["error"]["code"] == "PASSWORD_BREACHED"
