"""Integration tests pra POST /auth/resend-verification."""



class TestResend:
    async def test_unverified_user_receives_email(self, client, make_user, mailhog):
        await make_user(email="resend@test.com", verified=False)
        r = await client.post("/auth/resend-verification", json={"email": "resend@test.com"})
        assert r.status_code == 200
        assert "disponível" in r.json()["message"]
        msgs = await mailhog.wait_for(count=1)
        assert len(msgs) >= 1

    async def test_verified_user_no_email_sent(self, client, make_user, mailhog, wait_for_workers):
        await make_user(email="already@test.com", verified=True)
        r = await client.post("/auth/resend-verification", json={"email": "already@test.com"})
        assert r.status_code == 200
        # Mesma mensagem neutra
        assert "disponível" in r.json()["message"]
        await wait_for_workers()
        msgs = await mailhog.get_messages()
        assert len(msgs) == 0

    async def test_nonexistent_email_neutral_response(self, client, mailhog, wait_for_workers):
        r = await client.post("/auth/resend-verification", json={"email": "ghost@nowhere.com"})
        assert r.status_code == 200
        assert "disponível" in r.json()["message"]
        await wait_for_workers()
        msgs = await mailhog.get_messages()
        assert len(msgs) == 0

    async def test_rate_limit_per_email(self, client, make_user):
        await make_user(email="rlemail@test.com", verified=False)
        # RESEND_EMAIL = (1, 600) — 1 a cada 10min
        r1 = await client.post("/auth/resend-verification", json={"email": "rlemail@test.com"})
        assert r1.status_code == 200
        r2 = await client.post("/auth/resend-verification", json={"email": "rlemail@test.com"})
        assert r2.status_code == 429

    async def test_invalid_email_format_422(self, client):
        r = await client.post("/auth/resend-verification", json={"email": "notanemail"})
        assert r.status_code == 422
