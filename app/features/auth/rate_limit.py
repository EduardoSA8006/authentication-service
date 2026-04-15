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
