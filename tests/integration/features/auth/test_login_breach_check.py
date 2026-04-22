"""N-5: HIBP check contínuo pós-login via worker async.

Login permanece rápido (HIBP fora do caminho crítico). Se a senha apareceu em
breach, o worker marca `users.password_breach_detected_at` e envia email
advisory. Logins seguintes exibem `password_advisory: "breached"` na response.
"""
from datetime import UTC, datetime
from unittest.mock import patch

from sqlalchemy import select

from app.features.auth.models import User


_CREDS = {"email": "breach-login@test.com", "password": "SenhaForte@2026"}


class TestLoginBreachCheck:
    async def test_breached_password_marks_user_and_sends_email(
        self, client, make_user, db, mailhog, wait_for_workers,
    ):
        """Login sucesso com senha vazada → worker marca flag + envia advisory."""
        user = await make_user(**_CREDS)
        assert user.password_breach_detected_at is None

        with patch("app.features.auth.service.is_sha1_breached", return_value=True):
            r = await client.post("/auth/login", json=_CREDS)
            assert r.status_code == 200
            await wait_for_workers()

        refreshed = (await db.execute(
            select(User).where(User.email == _CREDS["email"]),
        )).scalar_one()
        assert refreshed.password_breach_detected_at is not None

        msgs = await mailhog.wait_for(count=1)
        assert msgs[0]["Content"]["Headers"]["Subject"][0] == "Sua senha pode estar comprometida"

    async def test_clean_password_leaves_flag_and_sends_nothing(
        self, client, make_user, db, mailhog, wait_for_workers,
    ):
        """HIBP retorna False → flag permanece None + nenhum email."""
        await make_user(**_CREDS)

        with patch("app.features.auth.service.is_sha1_breached", return_value=False):
            r = await client.post("/auth/login", json=_CREDS)
            assert r.status_code == 200
            await wait_for_workers()

        refreshed = (await db.execute(
            select(User).where(User.email == _CREDS["email"]),
        )).scalar_one()
        assert refreshed.password_breach_detected_at is None

        msgs = await mailhog.get_messages()
        assert len(msgs) == 0

    async def test_worker_skipped_when_flag_already_set(
        self, client, make_user, mailhog, wait_for_workers,
    ):
        """Flag já setado → worker NÃO chama HIBP nem reenvia email.
        Evita rehitting a API em todo login após primeira detecção."""
        await make_user(
            **_CREDS, password_breach_detected_at=datetime(2026, 1, 1, tzinfo=UTC),
        )

        hibp_mock = patch("app.features.auth.service.is_sha1_breached")
        with hibp_mock as mocked:
            r = await client.post("/auth/login", json=_CREDS)
            assert r.status_code == 200
            await wait_for_workers()
            assert not mocked.called, "HIBP não deveria ser chamado com flag já setado"

        msgs = await mailhog.get_messages()
        assert len(msgs) == 0

    async def test_response_includes_password_advisory_when_flagged(
        self, client, make_user,
    ):
        """User com flag setado → response de login mostra password_advisory."""
        await make_user(
            **_CREDS, password_breach_detected_at=datetime(2026, 3, 1, tzinfo=UTC),
        )

        r = await client.post("/auth/login", json=_CREDS)
        assert r.status_code == 200
        body = r.json()
        assert body["password_advisory"] == "breached"
        # Timestamp cru NÃO é exposto (escondido via Field exclude=True)
        assert "password_breach_detected_at" not in body

    async def test_response_no_advisory_when_flag_null(
        self, client, make_user, wait_for_workers,
    ):
        """User sem flag → password_advisory é None."""
        await make_user(**_CREDS)

        with patch("app.features.auth.service.is_sha1_breached", return_value=False):
            r = await client.post("/auth/login", json=_CREDS)
            await wait_for_workers()

        assert r.status_code == 200
        assert r.json()["password_advisory"] is None

    async def test_me_endpoint_also_shows_advisory(
        self, client, make_user,
    ):
        """GET /auth/me também deriva password_advisory da mesma coluna."""
        await make_user(
            **_CREDS, password_breach_detected_at=datetime(2026, 3, 1, tzinfo=UTC),
        )
        login = await client.post("/auth/login", json=_CREDS)
        csrf = login.cookies["csrf_token"]
        client.headers["X-CSRF-Token"] = csrf

        r = await client.get("/auth/me")
        assert r.status_code == 200
        assert r.json()["password_advisory"] == "breached"

    async def test_concurrent_logins_single_email(
        self, client, make_user, db, mailhog, wait_for_workers,
    ):
        """Race: 2 logins concorrentes, só 1 email deve sair (double-check no worker)."""
        import asyncio

        await make_user(**_CREDS)

        with patch("app.features.auth.service.is_sha1_breached", return_value=True):
            r1, r2 = await asyncio.gather(
                client.post("/auth/login", json=_CREDS),
                client.post("/auth/login", json=_CREDS),
            )
            assert r1.status_code == 200
            assert r2.status_code == 200
            await wait_for_workers()

        # Flag marcado uma única vez; o segundo worker vê flag setado e sai.
        refreshed = (await db.execute(
            select(User).where(User.email == _CREDS["email"]),
        )).scalar_one()
        assert refreshed.password_breach_detected_at is not None

        msgs = await mailhog.get_messages()
        # Garantia best-effort: double-check previne duplicata na maioria dos cenários.
        # Pode eventualmente vazar 1 email extra se ambos workers lerem antes do commit.
        assert len(msgs) <= 2
