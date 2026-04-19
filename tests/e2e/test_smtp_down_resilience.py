"""E2E: SMTP indisponível não quebra o register (fire-and-forget)."""
from unittest.mock import patch


from app.core.config import settings


class TestSMTPDownResilience:
    async def test_register_succeeds_even_with_bad_smtp_host(
        self, client, db, wait_for_workers,
    ):
        """Register-queue: handler retorna 202 antes mesmo do worker tentar SMTP.
        Falha de SMTP vira log silencioso no worker, invisível ao cliente."""
        with patch.object(settings, "SMTP_HOST", "nonexistent-smtp.invalid"):
            r = await client.post("/auth/register", json={
                "name": "Resilient User",
                "email": "resilient@test.com",
                "password": "SenhaForte@2026",
                "date_of_birth": "1990-01-01",
            })
            assert r.status_code == 202
            # Worker tenta SMTP → fail → log. Não propaga erro.
            await wait_for_workers()
