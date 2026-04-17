import logging
import re
import time
from urllib.parse import urlparse

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings
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

def _get_client_ip(request: Request) -> str:
    """Extract real client IP respecting trusted proxies only."""
    peer_ip = request.client.host if request.client else "unknown"
    if peer_ip in settings.TRUSTED_PROXY_IPS:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
    return peer_ip


def _stable_ua(ua: str) -> str:
    """Strip version numbers from UA for resilient session binding."""
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
# Rate Limiting (atomic fixed-window counter in Redis)
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        from app.core.redis import get_redis

        client_ip = _get_client_ip(request)
        window = int(time.time()) // settings.RATE_LIMIT_WINDOW
        key = f"rl:{client_ip}:{window}"

        try:
            redis = get_redis()
            pipe = redis.pipeline()
            pipe.incr(key)
            pipe.expire(key, settings.RATE_LIMIT_WINDOW, nx=True)
            count, _ = await pipe.execute()

            if count > settings.RATE_LIMIT_REQUESTS:
                pttl = await redis.pttl(key)
                retry_after = max(pttl // 1000, 1)
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
                set_session_cookies(response, new_token)
                request.state.session_token = new_token
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
