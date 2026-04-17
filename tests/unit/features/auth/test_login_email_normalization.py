"""Regression tests para L-3: LoginRequest normaliza email igual ao Register."""
from app.features.auth.schemas import LoginRequest


class TestLoginEmailNormalization:
    def test_lowercases(self):
        r = LoginRequest(email="USER@EXAMPLE.COM", password="SenhaForte@2026")
        assert r.email == "user@example.com"

    def test_strips_whitespace(self):
        r = LoginRequest(email="  user@example.com  ", password="SenhaForte@2026")
        assert r.email == "user@example.com"

    def test_invalid_format_falls_back_to_strip_lower(self):
        """Anti-enum: formato inválido não gera 422; passa valor normalizado
        pro service, que retorna InvalidCredentialsError."""
        r = LoginRequest(email="NOT-AN-EMAIL", password="SenhaForte@2026")
        # Não levanta ValidationError; valor fica normalizado como fallback
        assert r.email == "not-an-email"

    def test_preserves_plus_alias(self):
        r = LoginRequest(email="user+tag@example.com", password="SenhaForte@2026")
        assert r.email == "user+tag@example.com"
