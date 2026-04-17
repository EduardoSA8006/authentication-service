"""E2E: Argon2 rehash automático quando params são upgradados."""
from argon2 import PasswordHasher
from sqlalchemy import select

from app.features.auth.models import User


class TestPasswordRehash:
    async def test_login_rehashes_if_params_changed(
        self, client, db, make_user,
    ):
        # Cria user com hash de params weaker (time_cost mais baixo)
        weak_ph = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
        weak_hash = weak_ph.hash("SenhaForte@2026")

        user = await make_user(email="rehash@test.com", password="temp")
        user.password_hash = weak_hash
        await db.flush()

        # Login correto
        r = await client.post("/auth/login", json={
            "email": "rehash@test.com", "password": "SenhaForte@2026",
        })
        assert r.status_code == 200

        # Fetch user e checar hash mudou
        refreshed = (await db.execute(
            select(User).where(User.id == user.id)
        )).scalar_one()
        assert refreshed.password_hash != weak_hash
