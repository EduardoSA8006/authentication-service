"""Regression tests para L-3: LoginRequest normaliza email igual ao Register."""
import pytest
from pydantic import ValidationError
from app.features.auth.schemas import LoginRequest


class TestLoginEmailNormalization:
    def test_lowercases(self):
        r = LoginRequest(email="USER@EXAMPLE.COM", password="SenhaForte@2026")
        assert r.email == "user@example.com"

    def test_strips_whitespace(self):
        r = LoginRequest(email="  user@example.com  ", password="SenhaForte@2026")
        assert r.email == "user@example.com"

    def test_invalid_format_raises_validation_error(self):
        """Email inválido levanta ValidationError — validação estrita no schema."""
        with pytest.raises(ValidationError):
            LoginRequest(email="NOT-AN-EMAIL", password="SenhaForte@2026")

    def test_preserves_plus_alias(self):
        r = LoginRequest(email="user+tag@example.com", password="SenhaForte@2026")
        assert r.email == "user+tag@example.com"
