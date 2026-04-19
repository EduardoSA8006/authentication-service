"""Integration test: senha em breach HIBP é rejeitada silenciosamente no worker.

No register-queue pattern (N-2), HIBP roda no worker background. Usuário recebe
202 como qualquer outro caminho — nenhum bit de side-channel distingue breach
vs ok vs email duplicado. O worker simplesmente loga e retorna; user não é
criado e nenhum email é enviado."""
from unittest.mock import patch

from sqlalchemy import select

from app.features.auth.models import User


class TestRegisterRejectsBreachedPassword:
    async def test_breached_password_silently_rejected(
        self, client, db, mailhog, wait_for_workers,
    ):
        with patch("app.features.auth.service.is_password_breached", return_value=True):
            r = await client.post("/auth/register", json={
                "name": "Victim User",
                "email": "breached@test.com",
                "password": "SenhaForte@2026",
                "date_of_birth": "1990-01-01",
            })
            assert r.status_code == 202  # Resposta igual aos outros caminhos

            await wait_for_workers()

            # User não foi criado
            users = (await db.execute(
                select(User).where(User.email == "breached@test.com"),
            )).scalars().all()
            assert len(users) == 0

            # Nenhum email de verificação enviado
            msgs = await mailhog.get_messages()
            assert len(msgs) == 0
