"""Integration tests: POST /auth/change-password (autenticada)."""


_CREDS = {"email": "chpw@test.com", "password": "SenhaForte@2026"}


class TestChangePassword:
    async def test_requires_session(self, client):
        r = await client.post("/auth/change-password", json={"current_password": "any"})
        assert r.status_code == 401

    async def test_requires_csrf(self, client, make_user):
        await make_user(**_CREDS)
        await client.post("/auth/login", json=_CREDS)
        # Login setou session cookie mas sem header CSRF
        r = await client.post("/auth/change-password", json={"current_password": _CREDS["password"]})
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "CSRF_FAILED"

    async def test_correct_current_password_sends_email(
        self, logged_in_client, mailhog, wait_for_workers,
    ):
        user, client = logged_in_client
        r = await client.post("/auth/change-password", json={
            "current_password": "SenhaForte@2026",
        })
        assert r.status_code == 202
        await wait_for_workers()

        msgs = await mailhog.wait_for(count=1)
        # Subject pode vir RFC 2047-encoded (conteúdo ASCII passa in-tact neste caso).
        subject = msgs[0]["Content"]["Headers"]["Subject"][0]
        assert "troca de senha" in subject.lower().replace("=", "")

    async def test_wrong_current_password_401(
        self, logged_in_client, mailhog, wait_for_workers,
    ):
        user, client = logged_in_client
        r = await client.post("/auth/change-password", json={
            "current_password": "senhaErrada123!",
        })
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "INVALID_CREDENTIALS"
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        assert len(msgs) == 0

    async def test_rate_limit_per_user(self, logged_in_client, wait_for_workers):
        user, client = logged_in_client
        # CHANGE_PASSWORD_USER = (3, 3600)
        for _ in range(3):
            await client.post("/auth/change-password", json={
                "current_password": "SenhaForte@2026",
            })
        r = await client.post("/auth/change-password", json={
            "current_password": "SenhaForte@2026",
        })
        assert r.status_code == 429
        await wait_for_workers()
