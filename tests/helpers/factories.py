"""Funções standalone usadas fora de fixtures pytest.

Os fixtures em conftest.py (make_user, logged_in_client) são a interface
primária pra testes — este módulo é pra uso em scripts/setup utilitário.
"""
import re


def extract_token_from_email_body(body: str) -> str:
    """Extrai query param `token` de uma URL no corpo do email."""
    m = re.search(r"token=([A-Za-z0-9_-]+)", body)
    if not m:
        raise ValueError("No verification token found in body")
    return m.group(1)


def build_csrf_headers(csrf_token: str, origin: str = "http://localhost:3000") -> dict[str, str]:
    """Headers para request autenticada com CSRF + Origin válidos."""
    return {
        "X-CSRF-Token": csrf_token,
        "Origin": origin,
    }
