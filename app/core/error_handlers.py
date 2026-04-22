import logging

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.exceptions import AppError

logger = logging.getLogger(__name__)


def _error_body(code: str, message: str, details: dict | list | None = None) -> dict:
    body: dict = {"code": code, "message": message}
    if details is not None:
        body["details"] = details
    return {"error": body}


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

async def app_error_handler(_request: Request, exc: AppError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_body(exc.code, exc.message, exc.details),
        headers=exc.headers,
    )


async def validation_error_handler(
    _request: Request, exc: RequestValidationError,
) -> JSONResponse:
    details = [
        {
            "field": ".".join(str(loc) for loc in err["loc"]),
            "message": err["msg"],
            "type": err["type"],
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content=_error_body("VALIDATION_ERROR", "Request validation failed", details),
    )


async def http_error_handler(
    _request: Request, exc: StarletteHTTPException,
) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_body("HTTP_ERROR", str(exc.detail)),
        headers=getattr(exc, "headers", None),
    )


async def unhandled_error_handler(_request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception")
    message = str(exc) if settings.DEBUG else "Internal server error"
    return JSONResponse(
        status_code=500,
        content=_error_body("INTERNAL_ERROR", message),
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_error_handlers(app: FastAPI) -> None:
    # Starlette tipa add_exception_handler esperando Callable[Exception] — mas
    # o Python protocol é covariante nos args: um handler que aceita AppError
    # (subclasse de Exception) é sempre invocado com uma Exception concreta
    # em runtime. mypy não aceita a variância nesse contexto; type: ignore
    # localizado é a solução oficial recomendada (ver Starlette #1108).
    app.add_exception_handler(AppError, app_error_handler)  # type: ignore[arg-type]
    app.add_exception_handler(
        RequestValidationError, validation_error_handler,  # type: ignore[arg-type]
    )
    app.add_exception_handler(
        StarletteHTTPException, http_error_handler,  # type: ignore[arg-type]
    )
    app.add_exception_handler(Exception, unhandled_error_handler)
