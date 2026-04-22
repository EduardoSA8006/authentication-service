"""Integration tests: POST /auth/forgot-password.

Anti-enum: 202 sempre. Worker silencia email inexistente.
"""
from unittest.mock import patch


_VALID_EMAIL = "reset@test.com"


class TestForgotPassword:
    async def test_existing_email_schedules_reset(
        self, client, make_user, mailhog, wait_for_workers,
    ):
        await make_user(email=_VALID_EMAIL)
        r = await client.post("/auth/forgot-password", json={"email": _VALID_EMAIL})
        assert r.status_code == 202
        await wait_for_workers()

        msgs = await mailhog.wait_for(count=1)
        # Subject tem ç/ã → MailHog guarda RFC 2047-encoded. Match por substring.
        subject = msgs[0]["Content"]["Headers"]["Subject"][0]
        assert "Redefini" in subject and "senha" in subject

    async def test_nonexistent_email_returns_same_202(
        self, client, mailhog, wait_for_workers,
    ):
        """Anti-enum: resposta idêntica ao caso de email existente."""
        r = await client.post("/auth/forgot-password", json={"email": "ghost@test.com"})
        assert r.status_code == 202
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        assert len(msgs) == 0

    async def test_unverified_user_gets_no_email(
        self, client, make_user, mailhog, wait_for_workers,
    ):
        """Porta lateral: conta não verificada não deve receber reset-email —
        a prova de posse do inbox tem de passar pelo fluxo dedicado de
        verify-email (TTL 24h + HMAC-SHA256), não pelo reset (TTL 1h)."""
        await make_user(email="unverified@test.com", verified=False)
        r = await client.post(
            "/auth/forgot-password", json={"email": "unverified@test.com"},
        )
        assert r.status_code == 202  # mesma resposta, anti-enum
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        assert len(msgs) == 0

    async def test_soft_deleted_user_gets_no_email(
        self, client, make_user, db, mailhog, wait_for_workers,
    ):
        from datetime import UTC, datetime

        from sqlalchemy import update

        from app.features.auth.models import User

        await make_user(email="deleted@test.com")
        await db.execute(
            update(User).where(User.email == "deleted@test.com").values(
                deleted_at=datetime.now(UTC),
            ),
        )
        await db.flush()

        r = await client.post("/auth/forgot-password", json={"email": "deleted@test.com"})
        assert r.status_code == 202
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        assert len(msgs) == 0

    async def test_malformed_email_returns_422(
        self, client, wait_for_workers,
    ):
        """Schema-level: email mal-formado é 422 — leak aceitável (mesma
        superfície do /register), trade-off pra não poluir keyspace Redis
        com payloads arbitrários. Anti-enum continua valendo pra emails
        bem-formados (existente vs não-existente vs soft-deleted → todos 202)."""
        r = await client.post("/auth/forgot-password", json={"email": "not-an-email"})
        assert r.status_code == 422
        await wait_for_workers()

    async def test_rate_limit_per_ip(self, client, wait_for_workers):
        # FORGOT_PASSWORD_IP = (5, 3600)
        for i in range(5):
            await client.post("/auth/forgot-password", json={"email": f"x{i}@test.com"})
        r = await client.post("/auth/forgot-password", json={"email": "overflow@test.com"})
        assert r.status_code == 429
        await wait_for_workers()

    async def test_rate_limit_per_email(self, client, wait_for_workers):
        # FORGOT_PASSWORD_EMAIL = (3, 3600)
        for _ in range(3):
            await client.post("/auth/forgot-password", json={"email": "target@test.com"})
        r = await client.post("/auth/forgot-password", json={"email": "target@test.com"})
        assert r.status_code == 429
        await wait_for_workers()

    async def test_response_body_identical_for_enum_safety(
        self, client, make_user, wait_for_workers,
    ):
        """Anti-enum estrutural: body é idêntico pra email existente vs não."""
        await make_user(email="existing@enum.com")

        r_existing = await client.post("/auth/forgot-password", json={"email": "existing@enum.com"})
        await wait_for_workers()
        r_ghost = await client.post("/auth/forgot-password", json={"email": "ghost@enum.com"})
        await wait_for_workers()

        assert r_existing.status_code == r_ghost.status_code == 202
        assert r_existing.json() == r_ghost.json()

    async def test_smtp_failure_does_not_crash(
        self, client, make_user, wait_for_workers,
    ):
        """SMTP down no worker vira log, não 500 no cliente."""
        await make_user(email=_VALID_EMAIL)
        with patch(
            "app.features.auth.service.send_password_reset_email",
            side_effect=Exception("smtp down"),
        ):
            r = await client.post("/auth/forgot-password", json={"email": _VALID_EMAIL})
            assert r.status_code == 202
            await wait_for_workers()
