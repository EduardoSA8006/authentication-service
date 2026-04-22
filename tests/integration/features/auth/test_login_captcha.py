"""R-3: CAPTCHA como step-up em /auth/login quando Layer 2 do lockout dispara.

Fluxo:
- Sem CAPTCHA habilitado → Layer 2 continua hard-block (N-6 intact).
- Com CAPTCHA habilitado + Layer 2 estourada:
  - Sem token X-Captcha-Token → SUSPICIOUS_ACTIVITY (429)
  - Token inválido → CAPTCHA_INVALID (400)
  - Token válido → bypass + login prossegue normalmente
- Layer 1 NÃO é bypassável por CAPTCHA (protege contra brute force single-IP).
"""
from unittest.mock import patch

import pytest_asyncio

from app.core.config import settings
from app.features.auth.rate_limit import (
    _LOCKOUT_GLOBAL_THRESHOLD,
    _LOCKOUT_THRESHOLD,
    _lockout_global_key,
    record_login_failure,
)
from app.core.redis import get_redis


_EMAIL = "captcha-user@test.com"
_PASSWORD = "SenhaForte@2026"


@pytest_asyncio.fixture
async def captcha_on():
    """Habilita CAPTCHA com secret dummy durante o teste."""
    with patch.object(settings, "CAPTCHA_ENABLED", True), \
         patch.object(settings, "CAPTCHA_SECRET", "server-secret"):
        yield


@pytest_asyncio.fixture
async def captcha_off():
    """Desabilita CAPTCHA explicitamente. Default do settings é True,
    então testes que validam comportamento 'sem CAPTCHA' precisam deste
    patch para não cair no branch de verify_captcha."""
    with patch.object(settings, "CAPTCHA_ENABLED", False):
        yield


async def _saturate_layer_2(email: str) -> None:
    for i in range(_LOCKOUT_GLOBAL_THRESHOLD):
        await record_login_failure(email, f"10.0.{i // 256}.{i % 256}")


class TestLayer2WithoutCaptcha:
    async def test_hard_block_when_captcha_disabled(self, client, make_user, captcha_off):
        """CAPTCHA_ENABLED=False → N-6 hard block intacto."""
        await make_user(email=_EMAIL, password=_PASSWORD)
        await _saturate_layer_2(_EMAIL)

        r = await client.post("/auth/login", json={
            "email": _EMAIL, "password": _PASSWORD,
        })
        assert r.status_code == 429
        assert r.json()["error"]["code"] == "SUSPICIOUS_ACTIVITY"

    async def test_captcha_token_ignored_when_disabled(self, client, make_user, captcha_off):
        """Mesmo com header X-Captcha-Token, sem CAPTCHA_ENABLED não bypassa."""
        await make_user(email=_EMAIL, password=_PASSWORD)
        await _saturate_layer_2(_EMAIL)

        r = await client.post(
            "/auth/login",
            json={"email": _EMAIL, "password": _PASSWORD},
            headers={"X-Captcha-Token": "any-token"},
        )
        assert r.status_code == 429
        assert r.json()["error"]["code"] == "SUSPICIOUS_ACTIVITY"


class TestLayer2WithCaptcha:
    async def test_missing_token_returns_suspicious(
        self, client, make_user, captcha_on,
    ):
        await make_user(email=_EMAIL, password=_PASSWORD)
        await _saturate_layer_2(_EMAIL)

        r = await client.post("/auth/login", json={
            "email": _EMAIL, "password": _PASSWORD,
        })
        assert r.status_code == 429
        assert r.json()["error"]["code"] == "SUSPICIOUS_ACTIVITY"

    async def test_invalid_token_returns_captcha_invalid(
        self, client, make_user, captcha_on,
    ):
        await make_user(email=_EMAIL, password=_PASSWORD)
        await _saturate_layer_2(_EMAIL)

        with patch("app.features.auth.rate_limit.verify_captcha", return_value=False):
            r = await client.post(
                "/auth/login",
                json={"email": _EMAIL, "password": _PASSWORD},
                headers={"X-Captcha-Token": "bad-token"},
            )
        assert r.status_code == 400
        assert r.json()["error"]["code"] == "CAPTCHA_INVALID"

    async def test_valid_token_bypasses_and_logs_in(
        self, client, make_user, captcha_on,
    ):
        await make_user(email=_EMAIL, password=_PASSWORD)
        await _saturate_layer_2(_EMAIL)

        with patch("app.features.auth.rate_limit.verify_captcha", return_value=True):
            r = await client.post(
                "/auth/login",
                json={"email": _EMAIL, "password": _PASSWORD},
                headers={"X-Captcha-Token": "good-token"},
            )
        assert r.status_code == 200
        assert r.cookies.get("session")

    async def test_valid_captcha_wrong_password_still_401(
        self, client, make_user, captcha_on,
    ):
        """CAPTCHA bypassa Layer 2 mas senha errada ainda falha."""
        await make_user(email=_EMAIL, password=_PASSWORD)
        await _saturate_layer_2(_EMAIL)

        with patch("app.features.auth.rate_limit.verify_captcha", return_value=True):
            r = await client.post(
                "/auth/login",
                json={"email": _EMAIL, "password": "senhaErrada@2026"},
                headers={"X-Captcha-Token": "good-token"},
            )
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "INVALID_CREDENTIALS"

    async def test_successful_captcha_login_clears_global_counter(
        self, client, make_user, captcha_on,
    ):
        """Após CAPTCHA + senha correta, próxima tentativa não precisa de CAPTCHA."""
        await make_user(email=_EMAIL, password=_PASSWORD)
        await _saturate_layer_2(_EMAIL)

        redis = get_redis()
        # Confirma que global estava setado
        assert await redis.get(_lockout_global_key(_EMAIL)) is not None

        with patch("app.features.auth.rate_limit.verify_captcha", return_value=True):
            r = await client.post(
                "/auth/login",
                json={"email": _EMAIL, "password": _PASSWORD},
                headers={"X-Captcha-Token": "good-token"},
            )
        assert r.status_code == 200

        # Global foi limpo porque CAPTCHA foi validado + credenciais corretas
        assert await redis.get(_lockout_global_key(_EMAIL)) is None


# ASGI test client usa 127.0.0.1 como client.host. Pra saturar Layer 1 via
# record_login_failure (bypassing HTTP), precisamos usar esse IP.
_CLIENT_IP = "127.0.0.1"


class TestLayer1NotBypassable:
    async def test_layer_1_hard_locks_even_with_valid_captcha(
        self, client, make_user, captcha_on,
    ):
        """CAPTCHA não libera brute force de mesmo IP (Layer 1).
        Solver farms resolvendo CAPTCHAs não devem destravar hard-lock per-IP."""
        await make_user(email=_EMAIL, password=_PASSWORD)

        # Satura Layer 1 no IP do test client
        for _ in range(_LOCKOUT_THRESHOLD):
            await record_login_failure(_EMAIL, _CLIENT_IP)

        # Mesmo com CAPTCHA valido, Layer 1 bloqueia
        with patch("app.features.auth.rate_limit.verify_captcha", return_value=True):
            r = await client.post(
                "/auth/login",
                json={"email": _EMAIL, "password": _PASSWORD},
                headers={"X-Captcha-Token": "good-token"},
            )
        assert r.status_code == 429
        assert r.json()["error"]["code"] == "RATE_LIMITED"  # não SUSPICIOUS_ACTIVITY

    async def test_layer_2_bypass_then_layer_1_still_checks(
        self, client, make_user, captcha_on,
    ):
        """Estourar AMBAS: Layer 2 global + Layer 1 pair. CAPTCHA libera Layer 2,
        mas Layer 1 ainda bloqueia (per-IP). Response: 429 RATE_LIMITED."""
        await make_user(email=_EMAIL, password=_PASSWORD)

        # Satura Layer 1 no IP real do test client
        for _ in range(_LOCKOUT_THRESHOLD):
            await record_login_failure(_EMAIL, _CLIENT_IP)
        # Satura Layer 2 global com IPs rotados adicionais
        remaining = _LOCKOUT_GLOBAL_THRESHOLD - _LOCKOUT_THRESHOLD
        for i in range(remaining):
            await record_login_failure(_EMAIL, f"10.0.{i // 256}.{i % 256}")

        with patch("app.features.auth.rate_limit.verify_captcha", return_value=True):
            r = await client.post(
                "/auth/login",
                json={"email": _EMAIL, "password": _PASSWORD},
                headers={"X-Captcha-Token": "good-token"},
            )
        # Layer 2 bypassada; Layer 1 ainda bloqueia o IP do client
        assert r.status_code == 429
        assert r.json()["error"]["code"] == "RATE_LIMITED"


class TestVerifyCaptchaCalledWithCorrectIp:
    async def test_verify_receives_client_ip(
        self, client, make_user, captcha_on,
    ):
        """remote_ip passado ao provider é o client IP (validado via trusted proxies)."""
        await make_user(email=_EMAIL, password=_PASSWORD)
        await _saturate_layer_2(_EMAIL)

        with patch(
            "app.features.auth.rate_limit.verify_captcha",
            return_value=True,
        ) as mverify:
            await client.post(
                "/auth/login",
                json={"email": _EMAIL, "password": _PASSWORD},
                headers={"X-Captcha-Token": "good-token"},
            )
            args, _ = mverify.call_args
            token_arg, ip_arg = args
            assert token_arg == "good-token"
            assert ip_arg  # non-empty IP
