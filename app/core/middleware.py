import ipaddress
import logging
from datetime import UTC, datetime

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
from app.core.email import _ua_summary
from app.core.security import (
    clear_session_cookies,
    delete_session,
    get_session,
    ip_subnet,
    is_expired,
    needs_rotation,
    rotate_session,
    set_session_cookies,
    touch_session,
    verify_csrf_token,
)

logger = logging.getLogger(__name__)

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_ip(value: str) -> str | None:
    """Retorna IP canonicalizado (str) se parseável; None caso contrário.
    Canonicaliza para evitar que "127.0.0.001" e "127.0.0.1" virem chaves
    Redis distintas. Rejeita lixo (paths, emojis, strings gigantes) que
    poluiria keyspace, logs e templates de email."""
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def get_client_ip(request: Request) -> str:
    """Extract real client IP. Walks X-Forwarded-For right-to-left, skipping
    trusted proxies — picks the rightmost non-trusted IP (the real client as
    seen by our edge proxy). Mitigates spoofing: attacker-controlled XFF
    values end up leftmost after nginx's proxy_add_x_forwarded_for.

    Todo IP retornado é validado via ipaddress.ip_address — header arbitrário
    ("../../../etc/passwd", "A"*10k) vira "invalid" e não entra em keys de
    Redis (rl:global:{ip}), dicts de sessão, logs ou templates de email.
    Distinguimos dois sentinels: "unknown" (sem peer, ex: testes) e "invalid"
    (peer ou header presente mas não-parseável) — ajuda triagem em logs."""
    if request.client is None:
        return "unknown"

    peer_ip = request.client.host
    if peer_ip not in settings.TRUSTED_PROXY_IPS:
        return _valid_ip(peer_ip) or "invalid"

    forwarded = request.headers.get("x-forwarded-for", "")
    ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
    saw_untrusted_entry = False
    for ip in reversed(ips):
        if ip in settings.TRUSTED_PROXY_IPS:
            continue
        saw_untrusted_entry = True
        validated = _valid_ip(ip)
        if validated is not None:
            return validated

    real_ip = request.headers.get("x-real-ip", "").strip()
    if real_ip and real_ip not in settings.TRUSTED_PROXY_IPS:
        saw_untrusted_entry = True
        validated = _valid_ip(real_ip)
        if validated is not None:
            return validated

    # Saw a non-trusted header entry that failed validation: attacker-supplied
    # garbage. Fallback para peer_ip (o proxy) juntaria todos esses requests
    # num único bucket rl:global:127.0.0.1 → DoS amplification.
    if saw_untrusted_entry:
        return "invalid"

    # Tráfego interno: peer trusted, sem XFF/real-ip não-confiáveis. Usa peer_ip
    # (ex: health-check do LB, internal service-to-service).
    return _valid_ip(peer_ip) or "invalid"


def _check_origin(request: Request) -> JSONResponse | None:
    """Strict: para endpoints state-changing (CSRFMiddleware só chama aqui
    em métodos não-safe), exige header Origin presente e na allowlist.

    Referer NÃO é aceito como gate — browsers modernos sempre emitem Origin
    em requests cross-origin, mas o header pode ser suprimido por meta
    referrer, redirects de esquema e alguns plugins, então um atacante
    capaz de remover Origin poderia forjar Referer. Além disso, urlparse
    tem edge cases conhecidos (http://evil.com#@legit.com → netloc='evil.com',
    http:///\\\\legit.com → netloc vazio) que tornam a comparação frágil.
    Referer continua sendo logado quando Origin está ausente, apenas pra
    investigação de incidentes — nunca como autorização.

    Falhas são logadas em WARNING (não INFO) pra alertar SIEM/ops —
    mudança de trend em logs indica scan/ataque em andamento."""
    origin = request.headers.get("origin")
    client_ip = get_client_ip(request)

    if origin is None:
        referer = request.headers.get("referer", "")
        logger.warning(
            "CSRF gate failure: ORIGIN_MISSING (method=%s path=%s ip=%s referer=%r)",
            request.method, request.url.path, client_ip, referer[:200],
        )
        return _error_json(
            "ORIGIN_MISSING", "Origin header required", 403,
        )

    if origin not in settings.ALLOWED_ORIGINS:
        logger.warning(
            "CSRF gate failure: ORIGIN_REJECTED (method=%s path=%s ip=%s origin=%r)",
            request.method, request.url.path, client_ip, origin[:200],
        )
        return _error_json("ORIGIN_REJECTED", "Origin not allowed", 403)

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
# Rate Limiting (sliding window counter in Redis)
# ---------------------------------------------------------------------------

# Rotas de probing (LB health checks, métricas) NÃO podem ser rate-limitadas:
# AWS ALB/GCP LB/k8s probes batem a cada 10-30s. Se o bucket global lotar com
# tráfego legítimo, health checks começam a receber 429, o LB marca o target
# como unhealthy e drena instâncias — outage induzido pelo próprio limiter.
# Campos conhecidos da sessão (ver app.core.security.create_session). Log
# de sessão corrupta só reporta presence/absence destes — se Redis for
# comprometido e atacante injetar keys arbitrárias no JSON, eles não vazam
# pro stream de logs (onde podem ser ingested em SIEM/terminal).
_KNOWN_SESSION_FIELDS = frozenset({
    "user_id", "created_at", "last_active", "rotated_at",
    "ip", "user_agent", "rotated_from", "grace",
})


_RATE_LIMIT_EXEMPT_PATHS = frozenset({
    "/health",    # compat — alias de /livez
    "/livez",     # liveness probe (processo vivo)
    "/readyz",    # readiness probe (deps disponíveis)
    "/metrics",
})


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in _RATE_LIMIT_EXEMPT_PATHS:
            return await call_next(request)

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
            # Fail-closed: redis fora = 503. Fail-open permitiria bypass de rate
            # limit (atacante derruba Redis → requests passam sem contagem).
            # Trade-off consciente: indisponibilidade > bypass de proteção anti-abuse.
            logger.info("Rate limiter backend unavailable — failing closed (503)")
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
        # CORP same-site: impede cross-origin reads (Spectre-style speculative,
        # <img>/<script> embedding em origem hostil). same-site (não
        # same-origin) permite subdomínios legítimos do próprio produto —
        # auth.example.com e app.example.com convivem. COOP/COEP omitidos:
        # JSON API pura não tem cross-origin isolation requirements.
        response.headers["Cross-Origin-Resource-Policy"] = "same-site"

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
            # Se a response já começou (app em streaming), não há como reverter
            # bytes já enviados — silenciamos a exceção, o cliente verá connection
            # reset quando o body do request for abortado. Alternativa seria
            # forçar o cliente a receber 413, mas isso viola HTTP (já enviamos
            # 200 OK em start). Aceitamos o trade-off: cenário raríssimo (rota
            # ASGI streaming que também lê body incrementalmente).


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

        # Sessão pode vir corrupta do Redis (migration mal-feita, JSON parcial,
        # campo faltante). is_expired lê created_at/last_active — sem eles,
        # KeyError propaga como 500. Defensivo: qualquer erro de parsing
        # → deleta a sessão e segue como anônimo. Log em WARNING pra oobs.
        try:
            expired = is_expired(session)
        except (KeyError, ValueError, TypeError):
            if isinstance(session, dict):
                present = sorted(set(session.keys()) & _KNOWN_SESSION_FIELDS)
                unknown_count = len(set(session.keys()) - _KNOWN_SESSION_FIELDS)
                fields_repr = f"known={present} unknown_count={unknown_count}"
            else:
                fields_repr = "non-dict"
            logger.warning(
                "Corrupt session data — invalidating (%s)", fields_repr,
            )
            await delete_session(token)
            response = await call_next(request)
            clear_session_cookies(response)
            return response

        if expired:
            await delete_session(token)
            response = await call_next(request)
            clear_session_cookies(response)
            return response

        # User-Agent binding — hard reject on mismatch.
        #
        # Compara apenas (Browser, OS family) via _ua_summary — granularidade
        # suficiente pra rejeitar cookie reuso entre Chrome/Windows e
        # Firefox/Linux, mas tolerante a auto-update de versão do browser
        # (Chrome 130 → 131) que aconteceria durante uma sessão ativa.
        # Binding mais estreito (stable_ua, com asteriscos por versão) gerava
        # logout forçado em ~30% dos users/dia em fleets enterprise devido
        # a auto-update silencioso. A própria segurança disso é limitada
        # (UA é forjável trivialmente) — coarser é o trade-off certo.
        stored_ua = session.get("user_agent", "")
        request_ua = request.headers.get("user-agent", "")
        if stored_ua and _ua_summary(stored_ua) != _ua_summary(request_ua):
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

        # Detecção de mudança de rede: /24 IPv4 ou /48 IPv6. NÃO quebra a
        # sessão (mobile/VPN trocam de rede legitimamente), mas notifica
        # out-of-band pra vítima de cookie theft perceber. O session["ip"]
        # é atualizado em memória antes do touch_session pra evitar respam
        # na mesma sessão. Cross-session dedup é feito no próprio worker
        # via Redis SETNX com TTL de 1h.
        stored_ip = session.get("ip", "")
        current_ip = get_client_ip(request)
        stored_subnet = ip_subnet(stored_ip)
        current_subnet = ip_subnet(current_ip)
        if (
            stored_subnet is not None
            and current_subnet is not None
            and stored_subnet != current_subnet
        ):
            from app.features.auth.service import (
                _ip_change_notification_worker,
                _spawn,
            )
            _spawn(
                _ip_change_notification_worker(
                    session["user_id"], current_ip, request_ua,
                ),
                label=f"ip_change_notification:user_id={session['user_id']}",
            )
            session["ip"] = current_ip

        await touch_session(token, session)
        request.state.session = session
        request.state.session_token = token

        response = await call_next(request)

        if needs_rotation(session):
            try:
                new_token = await rotate_session(token, session)
                if new_token:
                    # TTL absoluto: max_age remanescente relativo ao created_at
                    # da sessão original, não a SESSION_TTL cheio. Sem isso,
                    # rotações horárias mantêm o cookie vivo indefinidamente.
                    created = datetime.fromisoformat(session["created_at"])
                    elapsed = int((datetime.now(UTC) - created).total_seconds())
                    remaining = max(settings.SESSION_TTL - elapsed, 1)
                    set_session_cookies(response, new_token, max_age=remaining)
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
            logger.warning(
                "CSRF gate failure: CSRF_FAILED (method=%s path=%s ip=%s "
                "header_present=%s)",
                request.method, request.url.path, get_client_ip(request),
                bool(csrf_token),
            )
            return _error_json("CSRF_FAILED", "CSRF validation failed", 403)

        return await call_next(request)
