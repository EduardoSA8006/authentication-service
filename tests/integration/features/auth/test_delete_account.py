"""Integration tests pra POST /auth/delete-account."""

from sqlalchemy import select

from app.features.auth.models import User


class TestDeleteAccount:
    async def test_happy_path_soft_deletes(self, logged_in_client, db):
        user, client = logged_in_client
        r = await client.post("/auth/delete-account", json={"password": "SenhaForte@2026"})
        assert r.status_code == 200

        refreshed = (await db.execute(
            select(User).where(User.id == user.id)
        )).scalar_one()
        assert refreshed.deleted_at is not None

    async def test_wrong_password_401(self, logged_in_client):
        user, client = logged_in_client
        r = await client.post("/auth/delete-account", json={"password": "SenhaErrada@9999"})
        assert r.status_code == 401

    async def test_revokes_sessions(self, logged_in_client):
        user, client = logged_in_client
        r = await client.post("/auth/delete-account", json={"password": "SenhaForte@2026"})
        assert r.status_code == 200
        # Sessão deve ter sido invalidada
        r2 = await client.get("/auth/me")
        assert r2.status_code == 401

    async def test_without_session_401(self, client):
        r = await client.post("/auth/delete-account", json={"password": "any"})
        assert r.status_code == 401
