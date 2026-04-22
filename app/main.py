import asyncio
import contextlib
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.responses import JSONResponse

from app.core.config import settings, validate_settings_for_production
from app.core.database import async_session
from app.core.error_handlers import register_error_handlers
from app.core.middleware import (
    CSRFMiddleware,
    RateLimitMiddleware,
    RequestIDMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
    SessionMiddleware,
)
from app.core.http_client import close_http_client, init_http_client
from app.core.redis import close_redis, get_redis, init_redis
from app.core.request_id import RequestIDFilter
from app.features.auth.service import (
    drain_background_tasks,
    purge_soft_deleted_users,
    warmup_password_hasher,
)

# Configura logging com request_id em toda linha — correlation pra incident response.
# force=True: uvicorn/outros frameworks podem ter chamado basicConfig antes
# do nosso import. Sem force, basicConfig é no-op quando handlers já existem,
# e o format com [%(request_id)s] nunca entra em vigor → request_id some
# do stream de logs, inutilizando correlation em incident response.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(request_id)s] %(levelname)s %(name)s: %(message)s",
    force=True,
)
for _handler in logging.root.handlers:
    _handler.addFilter(RequestIDFilter())

logger = logging.getLogger(__name__)

_PURGE_INTERVAL = 3600  # 1 hour
# Lock TTL próximo ao intervalo: purge em alta cardinalidade (milhares de users
# soft-deleted pendentes) pode exceder 300s. Se o lock expirar mid-run, outro
# worker sobe e faz double-work — purge é idempotente (DELETE WHERE cutoff)
# mas queima CPU/IO duplicado. TTL = intervalo - 5min deixa margem pra release
# manual antes do próximo tick sem deadlock entre instâncias.
_PURGE_LOCK_TTL = _PURGE_INTERVAL - 300  # 55 min


async def _purge_loop() -> None:
    """Periodically hard-delete users past the soft-delete retention window."""
    while True:
        await asyncio.sleep(_PURGE_INTERVAL)
        try:
            redis = get_redis()
            lock = redis.lock("purge_deleted_users_lock", timeout=_PURGE_LOCK_TTL)
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
    await init_http_client()
    # Aquecer o dummy hash do Argon2id ANTES de servir tráfego — tira o
    # primeiro ~300-500ms da lazy-init do path de login (oráculo de timing
    # para enumeração de usuários no cold-start).
    await warmup_password_hasher()
    task = asyncio.create_task(_purge_loop())
    yield
    task.cancel()
    # Aguarda o finally do _purge_loop rodar (release do lock Redis). Sem isso,
    # shutdown entre lock.acquire() e o release deixa o lock órfão por 300s
    # (TTL), bloqueando todos os workers até expirar.
    with contextlib.suppress(asyncio.CancelledError):
        await task

    # Drena tasks in-flight ANTES de fechar Redis/HTTP — evita que workers
    # mid-await batam em conexões já fechadas e percam trabalho silenciosamente.
    # Cobre SIGTERM (shutdown gracioso); SIGKILL/OOM continuam perdendo tasks
    # (sem fila durável). Timeout evita shutdown travar por worker lento.
    dropped = await drain_background_tasks(_SHUTDOWN_DRAIN_TIMEOUT)
    if dropped:
        logger.error(
            "Shutdown: %d background task(s) não completaram no timeout — "
            "verificar logs por 'scheduled' sem 'completed' pra reprocessar.",
            dropped,
        )
    # close_http_client e close_redis não têm timeout próprio: se a conexão
    # com Redis travar (network flap, kernel hung), o shutdown fica pendurado.
    # Aceitável na prática porque o orquestrador (k8s/compose) dispara SIGKILL
    # após ~30s de SIGTERM ignorado — processo é forçado a morrer. Adicionar
    # wait_for aqui pouparia os últimos segundos, mas complicaria o cleanup
    # de recursos pendentes sem benefício real.
    await close_http_client()
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
# Request flow: RequestID → TrustedHost → SecurityHeaders → CORS → RateLimit
#               → SizeLimit → Session → CSRF → Route
#
# RateLimit FICA DENTRO de CORS (early-return 429 precisa voltar pelo CORS
# pra carregar os Access-Control-Allow-* — senão o browser bloqueia a response
# como "network error" e o cliente JS não consegue ler Retry-After/status).
app.add_middleware(CSRFMiddleware)
app.add_middleware(SessionMiddleware)
app.add_middleware(RequestSizeLimitMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=[
        "Content-Type", settings.CSRF_HEADER_NAME, "X-Request-ID", "X-Captcha-Token",
    ],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
# RequestID deve ser o MAIS externo — todos os outros logs herdam o contextvar
app.add_middleware(RequestIDMiddleware)


from app.features.auth.router import router as auth_router  # noqa: E402

app.include_router(auth_router)


_READINESS_PROBE_TIMEOUT = 1.5  # por dependência; LB costuma expectar < 2s no total
_SHUTDOWN_DRAIN_TIMEOUT = 10.0  # aguarda workers drenarem antes do close


@app.get("/livez")
async def livez():
    """Liveness probe: 200 enquanto o processo responde. NÃO checa deps —
    LB usa isso pra detectar container morto (reiniciar pod), não pra drenagem.
    Checar Redis/DB aqui causaria restart em incidente de dependência,
    amplificando a falha em vez de só drenar tráfego."""
    return {"status": "ok"}


@app.get("/readyz")
async def readyz():
    """Readiness probe: 200 se Redis + DB respondem sob timeout. LB usa isso
    pra decidir se rotear tráfego; em 503, drena a instância sem matar o pod.
    Cada dependência tem timeout curto — total < 3s mesmo com ambas lentas.
    Resposta inclui o dependency quebrado pra diagnóstico (endpoint está em
    rede interna do LB, não exposto publicamente)."""
    deps: dict[str, str] = {}
    all_ok = True

    try:
        redis = get_redis()
        await asyncio.wait_for(redis.ping(), timeout=_READINESS_PROBE_TIMEOUT)
        deps["redis"] = "ok"
    except Exception as e:
        deps["redis"] = f"error: {type(e).__name__}"
        all_ok = False

    try:
        async with async_session() as db:
            await asyncio.wait_for(
                db.execute(text("SELECT 1")),
                timeout=_READINESS_PROBE_TIMEOUT,
            )
        deps["database"] = "ok"
    except Exception as e:
        deps["database"] = f"error: {type(e).__name__}"
        all_ok = False

    status_code = 200 if all_ok else 503
    return JSONResponse(
        {"status": "ok" if all_ok else "degraded", "dependencies": deps},
        status_code=status_code,
    )


# Alias de compat. Probes antigos continuam funcionando enquanto ops migra
# o LB config de /health para /livez (proc-alive) e /readyz (drain-ready).
@app.get("/health")
async def health():
    return {"status": "ok"}
