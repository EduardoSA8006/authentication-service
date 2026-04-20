import hashlib
import logging

from app.core.captcha import verify_captcha
from app.core.config import settings
from app.core.exceptions import RateLimitedError, ServiceUnavailableError
from app.core.redis import get_redis
from app.features.auth.exceptions import CaptchaInvalidError, SuspiciousActivityError

logger = logging.getLogger(__name__)


# Per-endpoint limits: (max_requests, window_seconds)
REGISTER_IP = (5, 60)
REGISTER_EMAIL = (3, 60)
LOGIN_IP = (10, 60)
LOGIN_EMAIL = (5, 300)
VERIFY_IP = (10, 60)
LOGOUT_IP = (10, 60)
DELETE_ACCOUNT_IP = (3, 60)
DELETE_ACCOUNT_USER = (5, 300)   # 5 por 5min por user — evita password probing via /delete
ME_IP = (30, 60)
RESEND_IP = (3, 3600)
RESEND_EMAIL = (1, 600)
FORGOT_PASSWORD_IP = (5, 3600)
FORGOT_PASSWORD_EMAIL = (3, 3600)  # 3 por hora por email-alvo — evita inbox spam
CHANGE_PASSWORD_IP = (5, 3600)
CHANGE_PASSWORD_USER = (3, 3600)
RESET_PASSWORD_IP = (10, 3600)  # mais generoso — usuário pode errar a nova senha

# ---------------------------------------------------------------------------
# Progressive lockout — duas camadas (N-6)
#
# Camada 1 (email, ip): threshold 10/15min. Protege contra brute force de um
#   único IP. Design por-par previne DoS via email conhecido (C-3): atacante
#   de um IP só se auto-lockoar; vítima em outro IP não é afetada.
#
# Camada 2 (email global): threshold 50/30min. Backstop contra IP rotation
#   (botnets, proxies residenciais) que bypassam Camada 1 trocando de IP.
#   Dispara SuspiciousActivityError em vez de RateLimitedError — sinaliza
#   para frontend/R-3 que step-up (CAPTCHA) é necessário.
# ---------------------------------------------------------------------------

_LOCKOUT_THRESHOLD = 10
_LOCKOUT_BASE_WINDOW = 900  # 15 minutes

_LOCKOUT_GLOBAL_THRESHOLD = 50
_LOCKOUT_GLOBAL_WINDOW = 1800  # 30 minutes


def _email_key(email: str) -> str:
    return hashlib.sha256(email.encode()).hexdigest()[:32]


def _lockout_key(email: str, ip: str) -> str:
    return f"login_failures:{_email_key(email)}:{ip}"


def _lockout_global_key(email: str) -> str:
    """Contador global por email — soma falhas de TODOS os IPs.
    Não é limpo em sucesso (evita atacante usar credential roubada pra
    resetar o counter e continuar); expira só pela TTL natural."""
    return f"login_failures_global:{_email_key(email)}"


async def check_login_lockout(
    email: str, ip: str, *, captcha_token: str | None = None,
) -> bool:
    """Camada 2 primeiro (ataque distribuído é mais grave) → Camada 1.
    Layer 2 dispara SuspiciousActivityError (pede step-up); Layer 1 dispara
    RateLimitedError (hard lock temporário).

    Retorna True se a request passou por CAPTCHA válido para bypass da Layer 2
    (caller deve limpar o contador global em sucesso, evita re-captcha no
    próximo login). False em qualquer outro caso.

    Layer 1 NÃO é bypassável por CAPTCHA — per-IP brute force não é mitigado
    por solver farms resolvendo CAPTCHAs."""
    captcha_used = False
    try:
        redis = get_redis()

        global_key = _lockout_global_key(email)
        count_global = await redis.get(global_key)
        if count_global and int(count_global) >= _LOCKOUT_GLOBAL_THRESHOLD:
            # Tentativa de bypass via CAPTCHA (se habilitado no settings)
            if settings.CAPTCHA_ENABLED and captcha_token:
                if not await verify_captcha(captcha_token, ip):
                    raise CaptchaInvalidError
                captcha_used = True
            else:
                pttl = await redis.pttl(global_key)
                retry_after = max(pttl // 1000, 1)
                raise SuspiciousActivityError(headers={"Retry-After": str(retry_after)})

        pair_key = _lockout_key(email, ip)
        count_pair = await redis.get(pair_key)
        if count_pair and int(count_pair) >= _LOCKOUT_THRESHOLD:
            pttl = await redis.pttl(pair_key)
            retry_after = max(pttl // 1000, 1)
            raise RateLimitedError(headers={"Retry-After": str(retry_after)})

        return captcha_used
    except (RateLimitedError, SuspiciousActivityError, CaptchaInvalidError):
        raise
    except Exception:
        logger.warning("Lockout check unavailable, rejecting request")
        raise ServiceUnavailableError


async def record_login_failure(email: str, ip: str) -> None:
    """Incrementa ambos contadores. Pair tem exponential backoff; global
    é fixed window (30min) — não precisa de backoff porque threshold 50
    já é bar alto e o TTL relativamente curto evita acumular ruído."""
    try:
        redis = get_redis()

        pair_key = _lockout_key(email, ip)
        pipe = redis.pipeline()
        pipe.incr(pair_key)
        pipe.expire(pair_key, _LOCKOUT_BASE_WINDOW, nx=True)
        count, _ = await pipe.execute()
        if count >= _LOCKOUT_THRESHOLD:
            factor = (count - _LOCKOUT_THRESHOLD) // 5
            new_window = min(_LOCKOUT_BASE_WINDOW * (2 ** factor), 3600)
            await redis.expire(pair_key, new_window)

        global_key = _lockout_global_key(email)
        pipe = redis.pipeline()
        pipe.incr(global_key)
        pipe.expire(global_key, _LOCKOUT_GLOBAL_WINDOW, nx=True)
        await pipe.execute()
    except Exception:
        logger.warning("Failed to record login failure")


async def clear_login_failures(
    email: str, ip: str, *, clear_global: bool = False,
) -> None:
    """Limpa o par (email, ip) em sucesso. O contador global só é limpo se
    `clear_global=True` — usado apenas quando CAPTCHA foi validado no caminho
    (gate de confiança: provou ser humano E tem credenciais válidas). Sem
    esse gate, atacante com credencial roubada poderia resetar o signal de
    suspeita. Por default global expira só pelo TTL natural (30min)."""
    try:
        redis = get_redis()
        pipe = redis.pipeline()
        pipe.delete(_lockout_key(email, ip))
        if clear_global:
            pipe.delete(_lockout_global_key(email))
        await pipe.execute()
    except Exception:
        pass
