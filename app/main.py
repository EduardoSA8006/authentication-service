import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.config import settings, validate_settings_for_production
from app.core.database import async_session
from app.core.error_handlers import register_error_handlers
from app.core.middleware import (
    CSRFMiddleware,
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
    SessionMiddleware,
)
from app.core.redis import close_redis, get_redis, init_redis
from app.features.auth.service import purge_soft_deleted_users

logger = logging.getLogger(__name__)

_PURGE_INTERVAL = 3600  # 1 hour


async def _purge_loop() -> None:
    """Periodically hard-delete users past the soft-delete retention window."""
    while True:
        await asyncio.sleep(_PURGE_INTERVAL)
        try:
            redis = get_redis()
            lock = redis.lock("purge_deleted_users_lock", timeout=300)
            if await lock.acquire(blocking=False):
                try:
                    async with async_session() as db:
                        await purge_soft_deleted_users(db)
                finally:
                    await lock.release()
        except Exception:
            logger.exception("Purge loop error")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    warnings = validate_settings_for_production()
    for w in warnings:
        if settings.is_production:
            raise RuntimeError(f"Startup blocked — {w}")
        logger.warning("Security: %s (allowed in development)", w)

    await init_redis()
    task = asyncio.create_task(_purge_loop())
    yield
    task.cancel()
    await close_redis()


app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)

register_error_handlers(app)

# Middleware stack — last added = outermost = runs first on request.
# Request flow: TrustedHost → SecurityHeaders → RateLimit → CORS
#               → SizeLimit → Session → CSRF → Route
app.add_middleware(CSRFMiddleware)
app.add_middleware(SessionMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Content-Type", settings.CSRF_HEADER_NAME],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)


from app.features.auth.router import router as auth_router  # noqa: E402

app.include_router(auth_router)


@app.get("/health")
async def health():
    return {"status": "ok"}
