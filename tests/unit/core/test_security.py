"""Unit tests para funções de segurança puras."""
from app.core.security import (
    _session_key,
    generate_csrf_token,
    generate_session_token,
    verify_csrf_token,
)


class TestCSRF:
    def test_deterministic(self):
        assert generate_csrf_token("session-a") == generate_csrf_token("session-a")

    def test_different_sessions_different_tokens(self):
        assert generate_csrf_token("a") != generate_csrf_token("b")

    def test_verify_accepts_valid(self):
        t = generate_csrf_token("session-x")
        assert verify_csrf_token("session-x", t) is True

    def test_verify_rejects_invalid(self):
        assert verify_csrf_token("session-x", "wrong-csrf") is False

    def test_verify_rejects_wrong_session(self):
        t = generate_csrf_token("a")
        assert verify_csrf_token("b", t) is False

    def test_hex_output(self):
        t = generate_csrf_token("s")
        assert all(c in "0123456789abcdef" for c in t)
        assert len(t) == 64  # sha256 hex


class TestSessionToken:
    def test_length(self):
        assert len(generate_session_token()) == 48

    def test_unique(self):
        tokens = {generate_session_token() for _ in range(100)}
        assert len(tokens) == 100

    def test_urlsafe_chars_only(self):
        import string
        allowed = set(string.ascii_letters + string.digits + "-_")
        t = generate_session_token()
        assert all(c in allowed for c in t)

    def test_redis_key_is_hashed(self):
        token = generate_session_token()
        key = _session_key(token)
        assert key.startswith("session:")
        assert token not in key  # raw token não aparece na chave
        assert len(key) == len("session:") + 64  # sha256 hex
