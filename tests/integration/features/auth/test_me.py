"""Integration tests pra GET /auth/me."""
from datetime import UTC, datetime



class TestMe:
    async def test_with_session_returns_user(self, logged_in_client):
        user, client = logged_in_client
        r = await client.get("/auth/me")
        assert r.status_code == 200
        data = r.json()
        assert data["email"] == "loggedin@test.com"
        assert data["is_verified"] is True
        assert data["name"] == "João Silva"

    async def test_without_session_401(self, client):
        r = await client.get("/auth/me")
        assert r.status_code == 401

    async def test_schema_matches(self, logged_in_client):
        user, client = logged_in_client
        r = await client.get("/auth/me")
        body = r.json()
        # Campos obrigatórios presentes
        assert set(body.keys()) >= {"id", "name", "email", "date_of_birth", "is_verified", "created_at"}

    async def test_soft_deleted_user_with_active_session_returns_401(
        self, logged_in_client, db,
    ):
        """Sessão ativa mas user.deleted_at setado → /me deve retornar 401.
        Defesa em profundidade: _get_user_by_id filtra deleted_at IS NULL."""
        user, client = logged_in_client

        # Soft-delete direto no DB sem invalidar sessão — simula o pior caso
        user.deleted_at = datetime.now(UTC)
        await db.commit()

        r = await client.get("/auth/me")
        assert r.status_code == 401
