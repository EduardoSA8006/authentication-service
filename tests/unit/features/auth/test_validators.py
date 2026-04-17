"""Unit tests para validators de entrada (NIST SP 800-63B + OWASP)."""
from datetime import date, timedelta

import pytest

from app.features.auth.validators import (
    validate_and_format_name,
    validate_and_normalize_email,
    validate_date_of_birth,
    validate_password,
)


class TestPassword:
    def test_rejects_shorter_than_8(self):
        with pytest.raises(ValueError, match="mínimo 8"):
            validate_password("Aa1@")

    def test_rejects_longer_than_128(self):
        with pytest.raises(ValueError, match="máximo 128"):
            validate_password("A1@" + "x" * 130)

    def test_rejects_missing_uppercase(self):
        with pytest.raises(ValueError, match="maiúscula"):
            validate_password("senha123@")

    def test_rejects_missing_digit(self):
        with pytest.raises(ValueError, match="número"):
            validate_password("SenhaForte@")

    def test_rejects_missing_special(self):
        with pytest.raises(ValueError, match="especial"):
            validate_password("SenhaForte2026")

    def test_rejects_common_password(self):
        with pytest.raises(ValueError, match="comum"):
            validate_password("P@ssw0rd")  # lowercase = "p@ssw0rd" que está na blocklist

    @pytest.mark.parametrize("pw", ["Abcd1234@", "Zyxw1234@"])
    def test_rejects_sequential(self, pw):
        with pytest.raises(ValueError, match="sequência"):
            validate_password(pw)

    def test_rejects_repeated(self):
        with pytest.raises(ValueError, match="sequência"):
            validate_password("Zaaaa12@")

    def test_rejects_contextual_name(self):
        with pytest.raises(ValueError, match="partes"):
            validate_password("JoaoX1@Qz", context=["Joao Silva"])

    def test_rejects_auth_keyword(self):
        # auth/authentication check só roda quando context é truthy
        with pytest.raises(ValueError, match="partes"):
            validate_password("AuthSecure1@", context=["John Doe"])

    def test_accepts_strong(self):
        validate_password("MyS3cur3P@ssphrase")


class TestName:
    def test_formats_uppercase_to_titlecase(self):
        assert validate_and_format_name("JOÃO DA SILVA") == "João da Silva"

    def test_preserves_apostrophe(self):
        assert validate_and_format_name("D'AVILA SANTOS") == "D'Avila Santos"

    def test_preserves_hyphen(self):
        assert validate_and_format_name("ana-maria costa") == "Ana-Maria Costa"

    def test_pt_br_lowercase_particles(self):
        assert validate_and_format_name("maria da silva dos santos") == "Maria da Silva dos Santos"

    def test_rejects_single_word(self):
        with pytest.raises(ValueError, match="2 palavras"):
            validate_and_format_name("Joao")

    def test_rejects_too_short(self):
        with pytest.raises(ValueError, match="2 caracteres"):
            validate_and_format_name("A")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError, match="120 caracteres"):
            validate_and_format_name("A" * 121 + " Silva")

    def test_rejects_digits(self):
        with pytest.raises(ValueError, match="inválidos"):
            validate_and_format_name("Jo4o Silva")

    def test_rejects_special_chars(self):
        with pytest.raises(ValueError, match="inválidos"):
            validate_and_format_name("João@ Silva")

    def test_collapses_multi_space(self):
        assert validate_and_format_name("Joao    Silva") == "Joao Silva"


class TestEmail:
    def test_lowercases(self):
        assert validate_and_normalize_email("Joao@Example.COM") == "joao@example.com"

    def test_strips_whitespace(self):
        assert validate_and_normalize_email("  test@example.com  ") == "test@example.com"

    def test_preserves_plus_alias(self):
        assert validate_and_normalize_email("user+tag@example.com") == "user+tag@example.com"

    def test_rejects_missing_at(self):
        with pytest.raises(ValueError):
            validate_and_normalize_email("notanemail")

    def test_rejects_missing_domain(self):
        with pytest.raises(ValueError):
            validate_and_normalize_email("test@")


class TestDateOfBirth:
    def test_accepts_valid(self):
        validate_date_of_birth(date(1990, 1, 1))

    def test_rejects_future(self):
        # +365 pra evitar edge case de timezone (dev local vs UTC do validator)
        future = date.today() + timedelta(days=365)
        with pytest.raises(ValueError, match="futuro"):
            validate_date_of_birth(future)

    def test_rejects_pre_1900(self):
        with pytest.raises(ValueError, match="inválida"):
            validate_date_of_birth(date(1899, 12, 31))

    def test_rejects_over_130_years(self):
        with pytest.raises(ValueError, match="inválida"):
            validate_date_of_birth(date.today().replace(year=date.today().year - 131))
