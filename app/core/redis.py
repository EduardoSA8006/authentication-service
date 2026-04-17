import redis.asyncio as aioredis

from app.core.config import settings

_redis: aioredis.Redis | None = None


async def init_redis() -> None:
    """Inicializa conexão Redis. Com REDIS_TLS=true, força verificação de
    certificado (CERT_REQUIRED + check_hostname). Sem isso, rediss:// só
    criptografa mas aceita qualquer certificado — MITM trivial."""
    global _redis
    kwargs: dict = {"decode_responses": True}
    if settings.REDIS_TLS:
        kwargs["ssl_cert_reqs"] = "required"
        kwargs["ssl_check_hostname"] = True
        if settings.REDIS_CA_CERT:
            kwargs["ssl_ca_certs"] = settings.REDIS_CA_CERT
    _redis = aioredis.from_url(settings.redis_url, **kwargs)


async def close_redis() -> None:
    global _redis
    if _redis is not None:
        await _redis.aclose()
        _redis = None


def get_redis() -> aioredis.Redis:
    if _redis is None:
        raise RuntimeError("Redis not initialized — call init_redis() first")
    return _redis
