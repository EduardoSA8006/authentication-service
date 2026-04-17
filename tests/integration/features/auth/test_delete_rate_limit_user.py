"""Regression tests para L-7: rate limit de delete-account por user_id."""


class TestDeleteAccountUserRateLimit:
    async def test_password_probing_blocked_by_user_limit(
        self, logged_in_client,
    ):
        """Testando senha errada 5 vezes → 6ª tentativa bloqueia (mesmo
        com senha correta seria bloqueado — impede probe via /delete)."""
        user, client = logged_in_client
        for _ in range(5):
            r = await client.post("/auth/delete-account", json={"password": "Wrong@1234"})
            # Pode ser 401 (senha errada) ou 429 (rate limit hit antes)
            assert r.status_code in (401, 429)

        # 6ª tentativa — limit hit (DELETE_ACCOUNT_USER = 5/5min)
        r = await client.post("/auth/delete-account", json={"password": "SenhaForte@2026"})
        assert r.status_code == 429
