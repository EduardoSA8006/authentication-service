"""Regression tests para C-3: lockout deve ser por (email, ip), não só email.
Evita DoS de conta por atacante que conhece email da vítima."""
from app.features.auth.rate_limit import check_login_lockout, record_login_failure


class TestLockoutScopedByIP:
    async def test_lockout_isolation_at_service_layer(self):
        """10 falhas do IP A → check_login_lockout do IP B não levanta (C-3)."""
        email = "target@test.com"

        for _ in range(10):
            await record_login_failure(email, "1.2.3.4")

        # Não deve levantar — o par (email, IP) é independente por design
        await check_login_lockout(email, "5.6.7.8")

    async def test_victim_can_login_despite_attacker_lockout(
        self, client, make_user,
    ):
        """HTTP: 10 falhas do IP A → login bem-sucedido do IP B (C-3).
        ASGITransport seta IP como 'unknown', que é distinto do IP do atacante."""
        await make_user(email="target2@test.com", password="SenhaForte@2026")

        for _ in range(10):
            await record_login_failure("target2@test.com", "1.2.3.4")

        r = await client.post("/auth/login", json={
            "email": "target2@test.com",
            "password": "SenhaForte@2026",
        })
        assert r.status_code == 200
