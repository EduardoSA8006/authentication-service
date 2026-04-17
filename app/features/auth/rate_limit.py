import logging

from app.core.exceptions import RateLimitedError, ServiceUnavailableError
from app.core.redis import get_redis

logger = logging.getLogger(__name__)


async def check_rate_limit(scope: str, key: str, limit: int, window: int) -> None:
    try:
        redis = get_redis()
        redis_key = f"rl:{scope}:{key}"
        pipe = redis.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, window, nx=True)
        count, _ = await pipe.execute()
        if count > limit:
            pttl = await redis.pttl(redis_key)
            retry_after = max(pttl // 1000, 1)
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
ME_IP = (30, 60)
RESEND_IP = (3, 3600)
RESEND_EMAIL = (1, 600)

# ---------------------------------------------------------------------------
# Progressive lockout (cumulative login failures)
# ---------------------------------------------------------------------------

_LOCKOUT_THRESHOLD = 10
_LOCKOUT_BASE_WINDOW = 900  # 15 minutes


async def check_login_lockout(email: str) -> None:
    """Block login if accumulated failures exceed threshold."""
    try:
        redis = get_redis()
        key = f"login_failures:{email}"
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


async def record_login_failure(email: str) -> None:
    """Increment failure counter with exponential backoff window."""
    try:
        redis = get_redis()
        key = f"login_failures:{email}"
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


async def clear_login_failures(email: str) -> None:
    """Clear failure counter on successful login."""
    try:
        redis = get_redis()
        await redis.delete(f"login_failures:{email}")
    except Exception:
        pass
