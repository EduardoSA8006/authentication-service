"""Unit tests pra sanitização de X-Request-ID."""
from app.core.request_id import new_request_id, sanitize_request_id


class TestSanitize:
    def test_strips_crlf(self):
        assert "\n" not in sanitize_request_id("abc\ndef")
        assert "\r" not in sanitize_request_id("abc\rdef")

    def test_truncates(self):
        assert len(sanitize_request_id("x" * 1000)) <= 64

    def test_keeps_alnum_hyphen_underscore(self):
        assert sanitize_request_id("abc-123_XYZ") == "abc-123_XYZ"

    def test_empty_falls_back_to_new_uuid(self):
        result = sanitize_request_id("")
        assert len(result) == 32  # UUID hex

    def test_all_invalid_chars_falls_back_to_new_uuid(self):
        result = sanitize_request_id("@#$%")
        assert len(result) == 32


class TestNewRequestID:
    def test_length_32_hex(self):
        assert len(new_request_id()) == 32

    def test_unique(self):
        assert len({new_request_id() for _ in range(100)}) == 100
