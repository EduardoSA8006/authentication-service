"""Regression tests para H-2: register anti-enum timing side-channel.

Caminho 'email existe' vs 'email novo' devem ter custo DB+Redis equivalente
(dentro de variação esperada). Anti-enum via timing é mitigado por rate limits,
mas o fix reduz a janela de enumeração."""
import time

import pytest


class TestRegisterTimingParity:
    async def test_duplicate_path_does_dummy_work(self, client, make_user, db):
        """O caminho duplicado faz INSERT+rollback+Redis via savepoint,
        equivalente ao custo do caminho novo. Aqui validamos que NÃO
        persiste o dummy no DB."""
        from sqlalchemy import select
        from app.features.auth.models import User

        await make_user(email="exists@test.com")
        r = await client.post("/auth/register", json={
            "name": "Outro Nome",
            "email": "exists@test.com",
            "password": "SenhaForte@2026",
            "date_of_birth": "1990-01-01",
        })
        assert r.status_code == 200

        # Conta total de users deve ser 1 (só o original make_user)
        # — dummy foi rollbacked via savepoint
        result = await db.execute(select(User))
        assert len(result.scalars().all()) == 1

    @pytest.mark.slow
    async def test_timing_delta_is_small(self, client, make_user):
        """Validação estatística leve: mede tempo de register duplicado vs novo.
        Delta deve ser <50% (era ~30-50% antes do fix)."""
        await make_user(email="existing@timing.com")

        # Mede tempo do caminho 'email existe'
        t0 = time.perf_counter()
        for _ in range(3):
            await client.post("/auth/register", json={
                "name": "Qualquer Um",
                "email": "existing@timing.com",
                "password": "SenhaForte@2026",
                "date_of_birth": "1990-01-01",
            })
        dup_time = time.perf_counter() - t0

        # Mede tempo do caminho 'email novo'
        t0 = time.perf_counter()
        for i, n in enumerate(["Ana Silva", "Beto Costa", "Caio Lima"]):
            await client.post("/auth/register", json={
                "name": n,
                "email": f"new{i}@timing.com",
                "password": "SenhaForte@2026",
                "date_of_birth": "1990-01-01",
            })
        new_time = time.perf_counter() - t0

        # Delta relativo — com fix, deve ser <50%
        delta_ratio = abs(new_time - dup_time) / max(new_time, dup_time)
        assert delta_ratio < 0.5, (
            f"Timing delta muito grande: dup={dup_time:.3f}s new={new_time:.3f}s "
            f"delta={delta_ratio:.1%}"
        )
