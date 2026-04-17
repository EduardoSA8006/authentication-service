"""Integration tests pra SecurityHeadersMiddleware."""


class TestSecurityHeaders:
    async def test_basic_headers_present(self, client):
        r = await client.get("/health")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["referrer-policy"] == "strict-origin-when-cross-origin"
        assert "camera=()" in r.headers["permissions-policy"]
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-xss-protection"] == "0"
        assert "default-src 'none'" in r.headers["content-security-policy"]

    async def test_hsts_not_in_test_env(self, client):
        # ENVIRONMENT=test → não é produção → sem HSTS
        r = await client.get("/health")
        assert "strict-transport-security" not in r.headers
