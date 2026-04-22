"""Integration tests: POST /auth/reset-password (consome token + persiste nova senha)."""
from datetime import UTC, datetime
from unittest.mock import patch

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from app.core.redis import get_redis
from app.features.auth.service import _create_reset_token, _reset_token_key


_EMAIL = "reset-apply@test.com"
_OLD_PASSWORD = "SenhaAntiga@2026"
_NEW_PASSWORD = "SenhaNovaForte@2027"


class TestResetPassword:
    async def test_valid_token_resets_password(
        self, client, make_user, db,
    ):
        user = await make_user(
            email=_EMAIL, password=_OLD_PASSWORD,
            password_breach_detected_at=datetime(2026, 1, 1, tzinfo=UTC),
            verified=False,
        )
        token = await _create_reset_token(str(user.id))

        r = await client.post("/auth/reset-password", json={
            "token": token, "new_password": _NEW_PASSWORD,
        })
        assert r.status_code == 200

        await db.refresh(user)
        ph = PasswordHasher()
        ph.verify(user.password_hash, _NEW_PASSWORD)  # nova senha funciona
        # Senha antiga não funciona mais
        try:
            ph.verify(user.password_hash, _OLD_PASSWORD)
            raise AssertionError("senha antiga ainda validou")
        except VerifyMismatchError:
            pass

        assert user.is_verified is True  # reset prova posse do email
        assert user.password_breach_detected_at is None  # flag limpo

    async def test_invalid_token_400(self, client):
        # Token com length válido (>=32 chars, Pydantic guard) mas não
        # registrado no Redis → INVALID_RESET_TOKEN no service, 400.
        r = await client.post("/auth/reset-password", json={
            "token": "a" * 43, "new_password": _NEW_PASSWORD,
        })
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "INVALID_RESET_TOKEN"

    async def test_expired_token_400(self, client, make_user):
        """Token que existiu no Redis e depois expirou → 400 igual a token inválido."""
        user = await make_user(email=_EMAIL, password=_OLD_PASSWORD)
        token = await _create_reset_token(str(user.id))

        # Simula expiração do TTL deletando a chave do Redis
        await get_redis().delete(_reset_token_key(token))

        r = await client.post("/auth/reset-password", json={
            "token": token, "new_password": _NEW_PASSWORD,
        })
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "INVALID_RESET_TOKEN"

    async def test_token_cannot_be_used_twice(self, client, make_user):
        """Regression: GETDEL atômico — token one-shot."""
        user = await make_user(email=_EMAIL, password=_OLD_PASSWORD)
        token = await _create_reset_token(str(user.id))

        r1 = await client.post("/auth/reset-password", json={
            "token": token, "new_password": _NEW_PASSWORD,
        })
        assert r1.status_code == 200

        r2 = await client.post("/auth/reset-password", json={
            "token": token, "new_password": "OutraSenha@2027",
        })
        assert r2.status_code == 400

    async def test_weak_password_400(self, client, make_user):
        # Passa o guard de schema (min_length=8) mas falha validate_password
        # (sem uppercase/digit/special) no service → WEAK_PASSWORD (400).
        # Valores <8 chars caem no schema e retornam 422 (ver test_oversized_password_422).
        user = await make_user(email=_EMAIL, password=_OLD_PASSWORD)
        token = await _create_reset_token(str(user.id))

        r = await client.post("/auth/reset-password", json={
            "token": token, "new_password": "senhafraca",
        })
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "WEAK_PASSWORD"

    async def test_contextual_password_400(self, client, make_user):
        """Nova senha não pode conter nome/email do usuário."""
        user = await make_user(
            email="johndoe@test.com", password=_OLD_PASSWORD,
            name="John Doe",
        )
        token = await _create_reset_token(str(user.id))

        r = await client.post("/auth/reset-password", json={
            "token": token, "new_password": "Johndoe@Senha2027",
        })
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "WEAK_PASSWORD"

    async def test_breached_password_400(self, client, make_user):
        user = await make_user(email=_EMAIL, password=_OLD_PASSWORD)
        token = await _create_reset_token(str(user.id))

        with patch("app.features.auth.service.is_password_breached", return_value=True):
            r = await client.post("/auth/reset-password", json={
                "token": token, "new_password": _NEW_PASSWORD,
            })
            assert r.status_code == 400
            assert r.json()["error"]["code"] == "PASSWORD_BREACHED"

    async def test_breached_keeps_token_consumed(self, client, make_user):
        """Edge case: token é consumido ANTES da validação de senha. Se rejeitar
        por senha fraca/breach, user precisa pedir novo token — não pode reusar."""
        user = await make_user(email=_EMAIL, password=_OLD_PASSWORD)
        token = await _create_reset_token(str(user.id))

        with patch("app.features.auth.service.is_password_breached", return_value=True):
            r1 = await client.post("/auth/reset-password", json={
                "token": token, "new_password": _NEW_PASSWORD,
            })
            assert r1.status_code == 400

        # Token já foi queimado no primeiro intento (GETDEL), mesmo com HIBP
        # rejeitando — retry com senha boa falha.
        r2 = await client.post("/auth/reset-password", json={
            "token": token, "new_password": _NEW_PASSWORD,
        })
        assert r2.status_code == 400
        assert r2.json()["error"]["code"] == "INVALID_RESET_TOKEN"

    async def test_reset_invalidates_all_sessions(
        self, logged_in_client, db,
    ):
        """Reset → todas as sessões existentes devem morrer (logout global)."""
        from app.core.security import list_user_sessions

        user, client = logged_in_client

        sessions_before = await list_user_sessions(str(user.id))
        assert len(sessions_before) == 1

        token = await _create_reset_token(str(user.id))
        r = await client.post("/auth/reset-password", json={
            "token": token, "new_password": _NEW_PASSWORD,
        })
        assert r.status_code == 200

        sessions_after = await list_user_sessions(str(user.id))
        assert len(sessions_after) == 0

    async def test_redis_key_is_hashed(self):
        """Defense-in-depth: token literal não vira chave Redis."""
        token = "raw-token-abc"
        key = _reset_token_key(token)
        assert token not in key
        assert key.startswith("password_reset:")

    async def test_rate_limit_per_ip(self, client, make_user):
        """RESET_PASSWORD_IP = (10, 3600) — 11º request bloqueado.
        Token length >=32 pra passar o Pydantic guard; value inválido garante
        que o service retorna 400 sem tocar DB (não consome state)."""
        await make_user(email=_EMAIL, password=_OLD_PASSWORD)
        bogus_token = "a" * 43

        for _ in range(10):
            await client.post("/auth/reset-password", json={
                "token": bogus_token, "new_password": _NEW_PASSWORD,
            })

        r = await client.post("/auth/reset-password", json={
            "token": bogus_token, "new_password": _NEW_PASSWORD,
        })
        assert r.status_code == 429

    async def test_oversized_password_422(self, client, make_user):
        """Pydantic max_length=128 bloqueia antes do service."""
        user = await make_user(email=_EMAIL, password=_OLD_PASSWORD)
        token = await _create_reset_token(str(user.id))

        r = await client.post("/auth/reset-password", json={
            "token": token, "new_password": "A@1" + "x" * 200,
        })
        assert r.status_code == 422
