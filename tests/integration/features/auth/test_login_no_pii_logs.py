"""Regression test pra M-1: logs de login não devem conter email em claro."""
import logging


class TestLoginLogsUseHashedEmail:
    async def test_user_not_found_logs_hashed_email(
        self, client, caplog,
    ):
        with caplog.at_level(logging.WARNING, logger="app.features.auth.service"):
            await client.post("/auth/login", json={
                "email": "ghost@test.com",
                "password": "SenhaForte@2026",
            })
        # Email em claro NÃO deve aparecer; hash sim
        log_text = " ".join(r.message for r in caplog.records)
        assert "ghost@test.com" not in log_text
        assert "hash=" in log_text
        assert "reason=user_not_found" in log_text

    async def test_wrong_password_logs_hashed_email(
        self, client, make_user, caplog,
    ):
        await make_user(email="real@test.com", password="SenhaForte@2026")
        with caplog.at_level(logging.WARNING, logger="app.features.auth.service"):
            await client.post("/auth/login", json={
                "email": "real@test.com",
                "password": "WrongPass@9999",
            })
        log_text = " ".join(r.message for r in caplog.records)
        assert "real@test.com" not in log_text
        assert "hash=" in log_text
        assert "reason=wrong_password" in log_text
