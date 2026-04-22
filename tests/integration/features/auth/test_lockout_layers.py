"""N-6: lockout em duas camadas (pair + global email).

Camada 1 (email, ip) a 10 falhas → RateLimitedError (RATE_LIMITED, 429).
Camada 2 (global email) a 50 falhas → SuspiciousActivityError (SUSPICIOUS_ACTIVITY, 429).

Layer 2 previne brute force distribuído via IP rotation — ataque comum com
botnets/proxies residenciais bypassaria o threshold por-par.
"""
import pytest

from app.core.exceptions import RateLimitedError
from app.core.security import hash_email
from app.features.auth.exceptions import SuspiciousActivityError
from app.features.auth.rate_limit import (
    _LOCKOUT_GLOBAL_THRESHOLD,
    _LOCKOUT_THRESHOLD,
    _lockout_global_key,
    _lockout_key,
    check_login_lockout,
    clear_login_failures,
    record_login_failure,
)
from app.core.redis import get_redis


_EMAIL = "target@test.com"


class TestLockoutLayer1Pair:
    async def test_pair_triggers_at_threshold(self, _clean_redis):
        ip = "1.2.3.4"
        for _ in range(_LOCKOUT_THRESHOLD):
            await record_login_failure(_EMAIL, ip)

        with pytest.raises(RateLimitedError):
            await check_login_lockout(_EMAIL, ip)

    async def test_pair_does_not_trigger_different_ip(self, _clean_redis):
        """IP diferente não é bloqueado pelo pair counter (design intencional)."""
        attacker_ip = "9.9.9.9"
        victim_ip = "1.2.3.4"

        for _ in range(_LOCKOUT_THRESHOLD):
            await record_login_failure(_EMAIL, attacker_ip)

        # Vítima em outro IP — pair (email, victim_ip) ainda zerado
        await check_login_lockout(_EMAIL, victim_ip)  # não levanta

    async def test_success_clears_pair_counter(self, _clean_redis):
        ip = "1.2.3.4"
        for _ in range(_LOCKOUT_THRESHOLD - 1):
            await record_login_failure(_EMAIL, ip)

        await clear_login_failures(_EMAIL, ip)

        # Depois do clear, pair counter zerado → mais 9 falhas não disparam
        for _ in range(_LOCKOUT_THRESHOLD - 1):
            await record_login_failure(_EMAIL, ip)
        await check_login_lockout(_EMAIL, ip)  # não levanta


class TestLockoutLayer2Global:
    async def test_global_triggers_with_ip_rotation(self, _clean_redis):
        """Simula IP rotation: 50 falhas cada uma de IP diferente.
        Pair counter nunca bate 10; global atinge 50 → SuspiciousActivityError."""
        for i in range(_LOCKOUT_GLOBAL_THRESHOLD):
            await record_login_failure(_EMAIL, f"10.0.0.{i}")

        # Qualquer IP agora é bloqueado pela Layer 2 — ataque distribuído detectado
        with pytest.raises(SuspiciousActivityError):
            await check_login_lockout(_EMAIL, "10.0.0.99")

        # Até IP nunca visto sofre — global é por email, não por IP
        with pytest.raises(SuspiciousActivityError):
            await check_login_lockout(_EMAIL, "192.168.0.1")

    async def test_global_survives_clear(self, _clean_redis):
        """Sucesso em um IP NÃO limpa o global — atacante com credencial roubada
        não pode resetar o signal de suspeita."""
        for i in range(_LOCKOUT_GLOBAL_THRESHOLD):
            await record_login_failure(_EMAIL, f"10.0.0.{i}")

        # Clear só mexe no pair
        await clear_login_failures(_EMAIL, "10.0.0.0")

        with pytest.raises(SuspiciousActivityError):
            await check_login_lockout(_EMAIL, "10.0.0.0")

    async def test_global_isolated_per_email(self, _clean_redis):
        """50 falhas em email A não bloqueia email B."""
        for i in range(_LOCKOUT_GLOBAL_THRESHOLD):
            await record_login_failure("victim-a@test.com", f"10.0.0.{i}")

        # Email diferente — counter isolado
        await check_login_lockout("victim-b@test.com", "10.0.0.0")  # não levanta

    async def test_global_threshold_takes_precedence(self, _clean_redis):
        """Quando ambos estouram, SuspiciousActivity é mais informativo — deve vir primeiro."""
        ip = "1.2.3.4"

        # Dispara ambos: 50 falhas do mesmo IP → pair=50, global=50
        for _ in range(_LOCKOUT_GLOBAL_THRESHOLD):
            await record_login_failure(_EMAIL, ip)

        # Ambos estão acima; check_login_lockout levanta Suspicious (verificado antes)
        with pytest.raises(SuspiciousActivityError):
            await check_login_lockout(_EMAIL, ip)


class TestLockoutRedisKeys:
    async def test_pair_key_format(self):
        key = _lockout_key("u@x.com", "1.2.3.4")
        assert key == f"login_failures:{hash_email('u@x.com')}:1.2.3.4"

    async def test_global_key_format(self):
        key = _lockout_global_key("u@x.com")
        assert key == f"login_failures_global:{hash_email('u@x.com')}"

    async def test_keys_are_distinct(self):
        """Layer 1 e Layer 2 vivem em chaves distintas."""
        assert _lockout_key("u@x.com", "1.2.3.4") != _lockout_global_key("u@x.com")


class TestLockoutIntegrationWithLogin:
    """End-to-end: após 50 falhas distribuídas, /auth/login devolve
    SUSPICIOUS_ACTIVITY em vez de INVALID_CREDENTIALS."""

    async def test_login_returns_suspicious_after_distributed_failures(
        self, client, make_user,
    ):
        await make_user(email=_EMAIL, password="SenhaForte@2026")

        # Simula ataque distribuído gravando falhas de muitos IPs
        for i in range(_LOCKOUT_GLOBAL_THRESHOLD):
            await record_login_failure(_EMAIL, f"10.0.{i // 256}.{i % 256}")

        # Agora login real (mesmo com senha CORRETA) é bloqueado por Layer 2
        r = await client.post("/auth/login", json={
            "email": _EMAIL, "password": "SenhaForte@2026",
        })
        assert r.status_code == 429
        assert r.json()["error"]["code"] == "SUSPICIOUS_ACTIVITY"
        assert "Retry-After" in r.headers

    async def test_global_ttl_is_set(self, _clean_redis):
        """Global counter tem TTL — não persiste indefinidamente."""
        await record_login_failure(_EMAIL, "1.2.3.4")

        redis = get_redis()
        pttl = await redis.pttl(_lockout_global_key(_EMAIL))
        assert pttl > 0  # TTL set
        assert pttl <= 1800 * 1000  # ≤ 30min em ms
