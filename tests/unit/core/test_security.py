"""Unit tests para funções de segurança puras."""
from app.core.security import (
    _session_key,
    generate_csrf_token,
    generate_session_token,
    ip_subnet,
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


class TestIPSubnet:
    def test_ipv4_collapses_to_24(self):
        """Mesmo /24 → mesma subnet (NAT/DHCP não dispara alerta)."""
        assert ip_subnet("192.168.1.10") == ip_subnet("192.168.1.250")

    def test_ipv4_different_24_differs(self):
        assert ip_subnet("192.168.1.10") != ip_subnet("192.168.2.10")

    def test_ipv6_collapses_to_48(self):
        """/48 IPv6: alocação típica de ISP para um cliente."""
        assert ip_subnet("2001:db8:abcd::1") == ip_subnet("2001:db8:abcd:ffff::1")

    def test_ipv6_different_48_differs(self):
        assert ip_subnet("2001:db8:abcd::1") != ip_subnet("2001:db8:abce::1")

    def test_sentinel_returns_none(self):
        assert ip_subnet("unknown") is None
        assert ip_subnet("invalid") is None

    def test_garbage_returns_none(self):
        assert ip_subnet("../../../etc/passwd") is None
        assert ip_subnet("") is None
