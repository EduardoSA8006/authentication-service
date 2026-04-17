"""E2E: SMTP indisponível não quebra o register (fire-and-forget)."""
from unittest.mock import patch


from app.core.config import settings


class TestSMTPDownResilience:
    async def test_register_succeeds_even_with_bad_smtp_host(self, client, db):
        """Simulating SMTP down: monkeypatch SMTP_HOST pra endereço inalcançável."""
        with patch.object(settings, "SMTP_HOST", "nonexistent-smtp.invalid"):
            r = await client.post("/auth/register", json={
                "name": "Resilient User",
                "email": "resilient@test.com",
                "password": "SenhaForte@2026",
                "date_of_birth": "1990-01-01",
            })
            # Register deve completar 200 mesmo com SMTP down (fire-and-forget)
            assert r.status_code == 200
