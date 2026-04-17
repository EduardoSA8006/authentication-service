import logging
import re
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings
from app.core.request_id import (
    new_request_id,
    sanitize_request_id,
    set_request_id,
)
from app.core.security import (
    clear_session_cookies,
    delete_session,
    get_session,
    is_expired,
    needs_rotation,
    rotate_session,
    set_session_cookies,
    touch_session,
    verify_csrf_token,
)

logger = logging.getLogger(__name__)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_UA_VERSIONS = re.compile(r"\d+\.\d+[\d.]*")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_client_ip(request: Request) -> str:
    """Extract real client IP. Walks X-Forwarded-For right-to-left, skipping
    trusted proxies — picks the rightmost non-trusted IP (the real client as
    seen by our edge proxy). Mitigates spoofing: attacker-controlled XFF
    values end up leftmost after nginx's proxy_add_x_forwarded_for."""
    peer_ip = request.client.host if request.client else "unknown"
    if peer_ip not in settings.TRUSTED_PROXY_IPS:
        return peer_ip

    forwarded = request.headers.get("x-forwarded-for", "")
    ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
    for ip in reversed(ips):
        if ip not in settings.TRUSTED_PROXY_IPS:
            return ip

    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip and real_ip not in settings.TRUSTED_PROXY_IPS:
        return real_ip

    return peer_ip


def _stable_ua(ua: str) -> str:
    """Strip version numbers from UA for resilient session binding.

    NOTA DE SEGURANÇA: UA binding NÃO é defesa séria — qualquer atacante forja
    User-Agent trivialmente. Este check só protege contra vetores triviais
    (ex: extensão maliciosa que rouba cookie mas mantém UA default do Chrome).
    Para detecção real de session hijacking, considerar fingerprint composto
    (IP+UA+Accept-Language) com tolerância, ou histórico de devices + notificação
    ao usuário em login novo."""
    return _UA_VERSIONS.sub("*", ua)


def _check_origin(request: Request) -> JSONResponse | None:
    """Validate Origin or Referer against ALLOWED_ORIGINS.
    Returns error response or None if valid."""
    origin = request.headers.get("origin")
    referer = request.headers.get("referer")

    if origin:
        if origin not in settings.ALLOWED_ORIGINS:
            return _error_json("ORIGIN_REJECTED", "Origin not allowed", 403)
    elif referer:
        parsed = urlparse(referer)
        referer_origin = f"{parsed.scheme}://{parsed.netloc}"
        if referer_origin not in settings.ALLOWED_ORIGINS:
            return _error_json("ORIGIN_REJECTED", "Origin not allowed", 403)
    else:
        return _error_json(
            "ORIGIN_MISSING",
            "Origin or Referer header required",
            403,
        )
    return None


def _error_json(code: str, message: str, status: int, headers: dict | None = None) -> JSONResponse:
    return JSONResponse(
        {"error": {"code": code, "message": message}},
        status_code=status,
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Request ID (correlation ID pra logs + response header)
# ---------------------------------------------------------------------------

class RequestIDMiddleware(BaseHTTPMiddleware):
    """Gera ou propaga X-Request-ID. Seta no contextvar pra logs, ecoa na response."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        incoming = request.headers.get("x-request-id", "")
        request_id = sanitize_request_id(incoming) if incoming else new_request_id()
        set_request_id(request_id)
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


# ---------------------------------------------------------------------------
# Rate Limiting (atomic fixed-window counter in Redis)
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        from app.core.rate_limit import sliding_window_incr

        client_ip = get_client_ip(request)
        key = f"rl:global:{client_ip}"

        try:
            count, retry_after = await sliding_window_incr(
                key,
                settings.RATE_LIMIT_REQUESTS,
                settings.RATE_LIMIT_WINDOW,
            )
            if count > settings.RATE_LIMIT_REQUESTS:
                return _error_json(
                    "RATE_LIMITED", "Too many requests", 429,
                    headers={"Retry-After": str(retry_after)},
                )
        except Exception:
            logger.warning("Rate limiter unavailable, rejecting request")
            return _error_json(
                "SERVICE_UNAVAILABLE",
                "Service temporarily unavailable",
                503,
            )

        return await call_next(request)


# ---------------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------------

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        # no-store globalmente — seguro enquanto este microserviço é puro JSON
        # API (nenhum endpoint serve assets estáticos, CSS, imagens). Se um dia
        # servir assets, refinar: só aplicar no-store em rotas com dados
        # sensíveis (ex: /auth/*, /me), deixar CSS/imagens com cache normal.
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'"
        )

        if settings.is_production:
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        return response


# ---------------------------------------------------------------------------
# Request Size Limit (raw ASGI — enforces on actual body, not just header)
# ---------------------------------------------------------------------------

class _BodyTooLarge(Exception):
    pass


class RequestSizeLimitMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Fast path: declared Content-Length
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                if int(value) > settings.MAX_REQUEST_SIZE:
                    resp = _error_json("PAYLOAD_TOO_LARGE", "Request body too large", 413)
                    await resp(scope, receive, send)
                    return
                break

        # Wrap receive to enforce limit on actual streamed bytes
        received = 0
        response_started = False

        async def sized_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > settings.MAX_REQUEST_SIZE:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, sized_receive, tracking_send)
        except _BodyTooLarge:
            if not response_started:
                resp = _error_json("PAYLOAD_TOO_LARGE", "Request body too large", 413)
                await resp(scope, receive, send)


# ---------------------------------------------------------------------------
# Session Lifecycle
# ---------------------------------------------------------------------------

class SessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.session = None
        request.state.session_token = None

        token = request.cookies.get(settings.session_cookie)
        if not token:
            return await call_next(request)

        try:
            session = await get_session(token)
        except Exception:
            logger.warning("Redis unavailable during session lookup")
            return await call_next(request)

        if session is None:
            response = await call_next(request)
            clear_session_cookies(response)
            return response

        if is_expired(session):
            await delete_session(token)
            response = await call_next(request)
            clear_session_cookies(response)
            return response

        # User-Agent binding — hard reject on mismatch
        stored_ua = session.get("user_agent", "")
        request_ua = request.headers.get("user-agent", "")
        if stored_ua and _stable_ua(stored_ua) != _stable_ua(request_ua):
            await delete_session(token)
            response = await call_next(request)
            clear_session_cookies(response)
            return response

        # Grace sessions: honour the short TTL, skip touch and rotation.
        # The 60s TTL set during rotation must not be extended.
        if session.get("grace"):
            request.state.session = session
            request.state.session_token = token
            return await call_next(request)

        await touch_session(token, session)
        request.state.session = session
        request.state.session_token = token

        response = await call_next(request)

        if needs_rotation(session):
            try:
                new_token = await rotate_session(token, session)
                if new_token:
                    set_session_cookies(response, new_token)
                    request.state.session_token = new_token
                # None = rotação concorrente venceu; essa request não toca cookies
            except Exception:
                logger.warning("Token rotation failed, keeping current token")

        return response


# ---------------------------------------------------------------------------
# CSRF (Signed Double-Submit Cookie)
# ---------------------------------------------------------------------------

class CSRFMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method in _SAFE_METHODS:
            return await call_next(request)

        # Use the validated session token from SessionMiddleware, not the raw cookie
        session_token = getattr(request.state, "session_token", None)
        if session_token is None:
            # No session: still validate Origin/Referer to prevent Login CSRF
            error = _check_origin(request)
            if error:
                return error
            return await call_next(request)

        error = _check_origin(request)
        if error:
            return error

        csrf_token = request.headers.get(settings.CSRF_HEADER_NAME)
        if not csrf_token or not verify_csrf_token(session_token, csrf_token):
            return _error_json("CSRF_FAILED", "CSRF validation failed", 403)

        return await call_next(request)
