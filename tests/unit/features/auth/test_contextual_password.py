"""Regression tests para H-1: _is_contextual falha com email (whitespace split)."""
import pytest

from app.features.auth.validators import validate_password


class TestContextualEmailRegression:
    def test_rejects_email_local_part_in_password(self):
        """Antes do fix, 'joaosilva@example.com'.split() = ['joaosilva@example.com']
        (string única) → check só dispara se email inteiro aparece na senha.
        Após fix: split em @._-+ pega 'joaosilva' como token."""
        with pytest.raises(ValueError, match="partes"):
            validate_password(
                "Joaosilva1@",
                context=["John Doe", "joaosilva@example.com"],
            )

    def test_rejects_email_domain_root(self):
        with pytest.raises(ValueError, match="partes"):
            validate_password(
                "Example1@!",
                context=["John Doe", "user@example.com"],
            )

    def test_rejects_dot_separated_name(self):
        """Split em . pega ambas as partes."""
        with pytest.raises(ValueError, match="partes"):
            validate_password(
                "Smith9X@Qy",
                context=["ignore", "john.smith@company.com"],
            )

    def test_rejects_hyphen_separated_email(self):
        with pytest.raises(ValueError, match="partes"):
            validate_password(
                "Acme9X@Qyz",
                context=["ignore", "contact@acme-corp.com"],
            )

    def test_still_accepts_unrelated_strong_password(self):
        # Context não aparece na senha → passa
        validate_password(
            "MyXy3Pzq!Wm",
            context=["John Doe", "john@example.com"],
        )
