"""Integration tests pra POST /auth/register."""
from sqlalchemy import select

from app.features.auth.models import User


_VALID_BODY = {
    "name": "João Silva",
    "email": "joao@test.com",
    "password": "SenhaForte@2026",
    "date_of_birth": "1990-01-01",
}


class TestRegister:
    async def test_happy_path_creates_user_and_sends_email(
        self, client, db, mailhog,
    ):
        r = await client.post("/auth/register", json=_VALID_BODY)
        assert r.status_code == 200
        assert "disponível" in r.json()["message"]

        user = (await db.execute(
            select(User).where(User.email == "joao@test.com")
        )).scalar_one()
        assert user.is_verified is False
        assert user.name == "João Silva"

        msgs = await mailhog.wait_for(count=1)
        assert msgs[0]["Content"]["Headers"]["Subject"][0] == "Confirme seu email"

    async def test_duplicate_email_returns_neutral(self, client, make_user, mailhog):
        await make_user(email="exists@test.com")
        r = await client.post("/auth/register", json={
            **_VALID_BODY, "email": "exists@test.com", "name": "Outro Nome",
        })
        assert r.status_code == 200
        assert "disponível" in r.json()["message"]

        # Nenhum email novo
        import asyncio
        await asyncio.sleep(0.1)
        msgs = await mailhog.get_messages()
        assert len(msgs) == 0

    async def test_short_password_rejected(self, client):
        r = await client.post("/auth/register", json={**_VALID_BODY, "password": "curta"})
        assert r.status_code == 422

    async def test_long_password_rejected(self, client):
        r = await client.post("/auth/register", json={
            **_VALID_BODY, "password": "A1@" + "x" * 130,
        })
        assert r.status_code == 422

    async def test_invalid_name_rejected(self, client):
        r = await client.post("/auth/register", json={**_VALID_BODY, "name": "João"})  # 1 palavra
        assert r.status_code == 422

    async def test_invalid_email_rejected(self, client):
        r = await client.post("/auth/register", json={**_VALID_BODY, "email": "notanemail"})
        assert r.status_code == 422

    async def test_future_dob_rejected(self, client):
        r = await client.post("/auth/register", json={
            **_VALID_BODY, "date_of_birth": "2099-01-01",
        })
        assert r.status_code == 422

    async def test_rate_limit_per_ip(self, client):
        # REGISTER_IP = (5, 60). Nomes só com letras (validator proíbe dígitos)
        names = ["Ana Silva", "Beto Costa", "Caio Lima", "Davi Souza", "Eva Reis"]
        for i, n in enumerate(names):
            await client.post("/auth/register", json={
                **_VALID_BODY, "email": f"ip{chr(97+i)}@test.com", "name": n,
            })
        r = await client.post("/auth/register", json={
            **_VALID_BODY, "email": "overflow@test.com", "name": "Over Flow",
        })
        assert r.status_code == 429
        assert "Retry-After" in r.headers

    async def test_rate_limit_per_email(self, client):
        # REGISTER_EMAIL = (3, 60). Mesmo email, nomes diferentes (qualquer vai ser
        # rejeitado por email-duplicado anti-enum, mas rate limit cobra)
        names = ["Ana Silva", "Beto Costa", "Caio Lima"]
        for n in names:
            await client.post("/auth/register", json={
                **_VALID_BODY, "email": "repeat@test.com", "name": n,
            })
        r = await client.post("/auth/register", json={
            **_VALID_BODY, "email": "repeat@test.com", "name": "Another Person",
        })
        assert r.status_code == 429

    async def test_origin_missing_blocked(self, client):
        # Remove Origin default; httpx não permite header "" → usar .headers.pop()
        client.headers.pop("Origin", None)
        r = await client.post(
            "/auth/register", json=_VALID_BODY,
            headers={"Referer": ""},  # força ausência de ambos
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "ORIGIN_MISSING"

    async def test_origin_wrong_blocked(self, client):
        r = await client.post(
            "/auth/register", json=_VALID_BODY,
            headers={"Origin": "http://evil.com"},
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "ORIGIN_REJECTED"
