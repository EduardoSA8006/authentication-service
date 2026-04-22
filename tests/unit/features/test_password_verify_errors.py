"""N-11: _ph.verify cobre VerifyMismatchError + InvalidHashError + VerificationError.

Hash corrompido no DB NÃO pode virar 500 — abriria oráculo (corrupção
distinguível de senha errada) e vazaria stack trace.
"""
from unittest.mock import AsyncMock, patch

import pytest

from app.features.auth.exceptions import InvalidCredentialsError
from app.features.auth.service import login_user


class _FakeUser:
    def __init__(self, corrupt_hash: str):
        self.id = "00000000-0000-0000-0000-000000000001"
        self.email = "corrupt@test.com"
        self.name = "User"
        self.password_hash = corrupt_hash
        self.is_verified = True
        self.password_breach_detected_at = None


class TestCorruptHashHandling:
    async def test_invalid_hash_returns_401_not_500(self):
        """Hash no DB sem formato Argon2 → InvalidHashError do _ph.verify
        → deve virar InvalidCredentialsError (401), não propagar como 500."""
        fake = _FakeUser(corrupt_hash="this-is-not-a-valid-argon2-hash")

        db_mock = AsyncMock()
        with patch(
            "app.features.auth.service._get_user_by_email", return_value=fake,
        ), patch(
            "app.features.auth.service.check_login_lockout", return_value=False,
        ), patch(
            "app.features.auth.service.record_login_failure", AsyncMock(),
        ):
            with pytest.raises(InvalidCredentialsError):
                await login_user(
                    email=fake.email,
                    password="any-password",
                    db=db_mock,
                    ip="1.2.3.4",
                    user_agent="test",
                )

    async def test_truncated_hash_returns_401(self):
        """Simula truncamento na coluna VARCHAR (col char limit < hash size)
        → InvalidHashError ou VerificationError. Ambos devem virar 401."""
        truncated = (
            "$argon2id$v=19$m=65536,t=3,p=4$"  # header OK
            "saltshort"                         # salt truncado
        )
        fake = _FakeUser(corrupt_hash=truncated)

        db_mock = AsyncMock()
        with patch(
            "app.features.auth.service._get_user_by_email", return_value=fake,
        ), patch(
            "app.features.auth.service.check_login_lockout", return_value=False,
        ), patch(
            "app.features.auth.service.record_login_failure", AsyncMock(),
        ):
            with pytest.raises(InvalidCredentialsError):
                await login_user(
                    email=fake.email,
                    password="any-password",
                    db=db_mock,
                    ip="1.2.3.4",
                    user_agent="test",
                )
