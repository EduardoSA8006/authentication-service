"""Regression tests para L-8: correlation ID por request."""


class TestRequestID:
    async def test_response_has_request_id_header(self, client):
        r = await client.get("/health")
        assert "x-request-id" in {k.lower() for k in r.headers}
        rid = r.headers.get("x-request-id")
        # UUID4 hex (32 chars) ou valor sanitizado do cliente
        assert rid and len(rid) >= 8

    async def test_generates_unique_id_per_request(self, client):
        r1 = await client.get("/health")
        r2 = await client.get("/health")
        assert r1.headers["x-request-id"] != r2.headers["x-request-id"]

    async def test_echoes_incoming_request_id(self, client):
        custom = "custom-trace-id-abc123"
        r = await client.get("/health", headers={"X-Request-ID": custom})
        assert r.headers["x-request-id"] == custom

    async def test_sanitizes_malicious_request_id(self, client):
        """CRLF no X-Request-ID seria log injection — invariante é 'sem CRLF'."""
        malicious = "abc\r\nX-Injected: yes"
        r = await client.get("/health", headers={"X-Request-ID": malicious})
        rid = r.headers["x-request-id"]
        assert "\r" not in rid
        assert "\n" not in rid
        assert ":" not in rid  # sem header-separator
        assert " " not in rid  # sem space (nosso allowlist rejeita)

    async def test_truncates_long_request_id(self, client):
        long_id = "x" * 500
        r = await client.get("/health", headers={"X-Request-ID": long_id})
        assert len(r.headers["x-request-id"]) <= 64
