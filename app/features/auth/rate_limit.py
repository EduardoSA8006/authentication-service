import logging

from app.core.exceptions import RateLimitedError, ServiceUnavailableError
from app.core.rate_limit import sliding_window_incr
from app.core.redis import get_redis

logger = logging.getLogger(__name__)


async def check_rate_limit(scope: str, key: str, limit: int, window: int) -> None:
    """Per-endpoint rate limit via sliding window.
    Raises RateLimitedError se excedido, ServiceUnavailableError se Redis down."""
    try:
        redis_key = f"rl:{scope}:{key}"
        count, retry_after = await sliding_window_incr(redis_key, limit, window)
        if count > limit:
            raise RateLimitedError(headers={"Retry-After": str(retry_after)})
    except RateLimitedError:
        raise
    except Exception:
        logger.warning("Rate limit unavailable for %s, rejecting request", scope)
        raise ServiceUnavailableError


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

# ---------------------------------------------------------------------------
# Progressive lockout (cumulative login failures)
# ---------------------------------------------------------------------------

_LOCKOUT_THRESHOLD = 10
_LOCKOUT_BASE_WINDOW = 900  # 15 minutes


def _lockout_key(email: str, ip: str) -> str:
    """Lockout é por (email, ip) — impede DoS de conta via email conhecido.
    Atacante de um IP consegue se auto-lockar, vítima em outro IP não é afetada."""
    return f"login_failures:{email}:{ip}"


async def check_login_lockout(email: str, ip: str) -> None:
    """Block login if accumulated failures for this (email, ip) pair exceed threshold."""
    try:
        redis = get_redis()
        key = _lockout_key(email, ip)
        count = await redis.get(key)
        if count and int(count) >= _LOCKOUT_THRESHOLD:
            pttl = await redis.pttl(key)
            retry_after = max(pttl // 1000, 1)
            raise RateLimitedError(headers={"Retry-After": str(retry_after)})
    except RateLimitedError:
        raise
    except Exception:
        logger.warning("Lockout check unavailable, rejecting request")
        raise ServiceUnavailableError


async def record_login_failure(email: str, ip: str) -> None:
    """Increment failure counter with exponential backoff window."""
    try:
        redis = get_redis()
        key = _lockout_key(email, ip)
        pipe = redis.pipeline()
        pipe.incr(key)
        pipe.expire(key, _LOCKOUT_BASE_WINDOW, nx=True)
        count, _ = await pipe.execute()
        if count >= _LOCKOUT_THRESHOLD:
            factor = (count - _LOCKOUT_THRESHOLD) // 5
            new_window = min(_LOCKOUT_BASE_WINDOW * (2 ** factor), 3600)
            await redis.expire(key, new_window)
    except Exception:
        logger.warning("Failed to record login failure")


async def clear_login_failures(email: str, ip: str) -> None:
    """Clear failure counter on successful login."""
    try:
        redis = get_redis()
        await redis.delete(_lockout_key(email, ip))
    except Exception:
        pass
