"""GET /auth/sessions + DELETE /auth/sessions/{id}.

Invariantes verificados:
- Listagem NÃO expõe token, UA bruto, nem IP completo.
- Ownership enforcement: user B não revoga sessão de user A (404, não 403).
- session_id malformado → 400 com INVALID_SESSION_ID.
- Revogar a própria sessão atual limpa os cookies.
- Endpoints exigem auth; CSRF obrigatório no DELETE.
"""
from app.core.security import create_session, session_id_from_token


_EMAIL = "sess@test.com"
_PASSWORD = "SenhaForte@2026"


class TestListSessions:
    async def test_requires_auth(self, client):
        r = await client.get("/auth/sessions")
        assert r.status_code == 401

    async def test_lists_own_sessions_only(self, logged_in_client, make_user):
        user, client = logged_in_client
        # Outro user com sessão concorrente — não deve aparecer na listagem
        other = await make_user(email="other@test.com", password=_PASSWORD)
        await create_session(
            str(other.id), ip="1.2.3.4", user_agent="Mozilla/5.0 Chrome/131.0",
        )

        r = await client.get("/auth/sessions")
        assert r.status_code == 200
        sessions = r.json()["sessions"]
        assert len(sessions) == 1
        assert sessions[0]["is_current"] is True

    async def test_marks_current_session(self, logged_in_client):
        user, client = logged_in_client
        # Sessão extra pro mesmo user — só a do request deve ter is_current=True
        await create_session(
            str(user.id), ip="203.0.113.10",
            user_agent="Mozilla/5.0 Firefox/130.0",
        )
        r = await client.get("/auth/sessions")
        assert r.status_code == 200
        sessions = r.json()["sessions"]
        assert len(sessions) == 2
        current = [s for s in sessions if s["is_current"]]
        assert len(current) == 1

    async def test_response_omits_sensitive_fields(self, logged_in_client):
        """Response NÃO deve conter user_agent bruto, IP cheio, nem token."""
        user, client = logged_in_client
        r = await client.get("/auth/sessions")
        sessions = r.json()["sessions"]
        s = sessions[0]

        # Whitelist de campos permitidos
        allowed = {
            "session_id", "created_at", "last_active",
            "ip_prefix", "device", "is_current",
        }
        assert set(s.keys()) == allowed
        # Device é resumo, não UA bruto
        assert "/" not in s["device"]  # sem "Chrome/131.0.6778.204"
        # ip_prefix é uma subnet (tem "/") ou null
        if s["ip_prefix"] is not None:
            assert "/" in s["ip_prefix"]


class TestRevokeSession:
    async def test_requires_auth(self, client):
        r = await client.delete(f"/auth/sessions/{'a' * 64}")
        assert r.status_code == 401

    async def test_requires_csrf(self, logged_in_client):
        user, client = logged_in_client
        # Remove header CSRF — sem ele, DELETE é rejeitado
        client.headers.pop("X-CSRF-Token", None)
        r = await client.delete(f"/auth/sessions/{'a' * 64}")
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "CSRF_FAILED"

    async def test_malformed_id_returns_400(self, logged_in_client):
        user, client = logged_in_client
        r = await client.delete("/auth/sessions/not-hex")
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "INVALID_SESSION_ID"

    async def test_path_traversal_attempt_rejected(self, logged_in_client):
        """session_id arbitrário não pode virar key Redis fora do namespace."""
        user, client = logged_in_client
        r = await client.delete("/auth/sessions/..%2Ffoo")
        assert r.status_code in (400, 404)  # path decode → INVALID_SESSION_ID ou 404 de rota

    async def test_nonexistent_session_returns_404(self, logged_in_client):
        user, client = logged_in_client
        fake_id = "f" * 64
        r = await client.delete(f"/auth/sessions/{fake_id}")
        assert r.status_code == 404
        assert r.json()["error"]["code"] == "SESSION_NOT_FOUND"

    async def test_cannot_revoke_other_users_session(
        self, logged_in_client, make_user,
    ):
        """Unified 404 com "não existe" — evita oráculo de enumeração."""
        user_a, client_a = logged_in_client
        user_b = await make_user(email="victim@test.com", password=_PASSWORD)
        other_token = await create_session(
            str(user_b.id), ip="1.2.3.4", user_agent="Mozilla/5.0 Safari/605",
        )
        other_sid = session_id_from_token(other_token)

        r = await client_a.delete(f"/auth/sessions/{other_sid}")
        assert r.status_code == 404
        assert r.json()["error"]["code"] == "SESSION_NOT_FOUND"

    async def test_revokes_specific_session(self, logged_in_client):
        """Revogar uma sessão secundária não afeta a sessão atual."""
        user, client = logged_in_client
        other_token = await create_session(
            str(user.id), ip="198.51.100.10",
            user_agent="Mozilla/5.0 Firefox/130.0",
        )
        other_sid = session_id_from_token(other_token)

        r = await client.delete(f"/auth/sessions/{other_sid}")
        assert r.status_code == 200

        # Sessão atual ainda funciona (/me OK)
        r2 = await client.get("/auth/me")
        assert r2.status_code == 200

        # Sessão revogada sumiu da listagem
        r3 = await client.get("/auth/sessions")
        sids = [s["session_id"] for s in r3.json()["sessions"]]
        assert other_sid not in sids

    async def test_revoke_self_clears_cookies(self, logged_in_client):
        """Revogar a sessão atual limpa cookies (UI alinhada ao backend)."""
        user, client = logged_in_client
        current_token = client.cookies.get("session")
        current_sid = session_id_from_token(current_token)

        r = await client.delete(f"/auth/sessions/{current_sid}")
        assert r.status_code == 200

        # Cookie de sessão foi sobrescrito com expiração → próximo /me 401
        r2 = await client.get("/auth/me")
        assert r2.status_code == 401


class TestRateLimitSessions:
    async def test_list_rate_limited(self, logged_in_client):
        """SESSIONS_LIST_IP = (30, 60) — 31º request bloqueado."""
        user, client = logged_in_client
        for _ in range(30):
            await client.get("/auth/sessions")
        r = await client.get("/auth/sessions")
        assert r.status_code == 429

    async def test_revoke_rate_limited(self, logged_in_client):
        """SESSIONS_REVOKE_IP = (10, 60) — 11º request bloqueado, mesmo
        que todos retornariam 404 (rate limit roda antes do service)."""
        user, client = logged_in_client
        fake = "f" * 64
        for _ in range(10):
            await client.delete(f"/auth/sessions/{fake}")
        r = await client.delete(f"/auth/sessions/{fake}")
        assert r.status_code == 429
