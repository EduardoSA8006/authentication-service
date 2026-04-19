"""E2E: N-2 register-queue pattern — handler não toca DB/HIBP/SMTP.

Arquitetura nova (Auth0/Clerk style): handler faz rate_limit + schedule + 202.
Todo trabalho pesado (HIBP, Argon2, INSERT, SMTP) vive no worker assíncrono.
Por construção, não há oráculo de timing — cada caminho (novo, duplicado,
breached) executa exatamente o mesmo código no handler."""
import time

from sqlalchemy import select

from app.features.auth.models import User


_BODY = {
    "name": "Alice Tester",
    "password": "SenhaForte@2026",
    "date_of_birth": "1990-01-01",
}


class TestRegisterQueuePattern:
    async def test_duplicate_email_creates_no_ghost_row(
        self, client, make_user, db, wait_for_workers,
    ):
        """Worker detecta duplicado via SELECT, retorna sem INSERT.
        Nada de savepoints/dummy rows — padrão antigo era propenso a bug."""
        await make_user(email="ghost@test.com")

        r = await client.post("/auth/register", json={**_BODY, "email": "ghost@test.com"})
        assert r.status_code == 202
        await wait_for_workers()

        users = (await db.execute(
            select(User).where(User.email == "ghost@test.com"),
        )).scalars().all()
        # Apenas o original; worker não criou fantasma.
        assert len(users) == 1

    async def test_handler_latency_bounded(self, client, make_user, wait_for_workers):
        """Structural guarantee: handler response time é independente do path.

        Handler roda: rate_limit (2× Redis ZSET) + _spawn + response +
        middleware stack. Em local ~5-20ms; budget 150ms absorve CI jitter.
        O ponto: << custo Argon2 (~100-500ms) que está no worker — se
        timing discriminasse email, handler teria que hashear no path real.
        """
        await make_user(email="existing@lat.com")

        # Warm-up: primeira request do test costuma ser mais lenta (connection
        # pool init, pydantic cache miss). Descarta esse sample.
        await client.post("/auth/register", json={
            **_BODY, "email": "warmup@lat.com", "name": "Warm Up",
        })
        await wait_for_workers()

        latencies = {}
        for label, email in [
            ("existing", "existing@lat.com"),
            ("new", "brandnew@lat.com"),
        ]:
            t0 = time.perf_counter()
            r = await client.post("/auth/register", json={
                **_BODY, "email": email, "name": "Lat User",
            })
            latencies[label] = time.perf_counter() - t0
            assert r.status_code == 202
            await wait_for_workers()

        for label, elapsed in latencies.items():
            assert elapsed < 0.15, (
                f"Handler latency ({label}) excedeu 150ms: {elapsed*1000:.1f}ms"
            )
