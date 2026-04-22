"""Singleton httpx.AsyncClient compartilhado entre HIBP, CAPTCHA e outros
chamadores HTTP externos.

Sem singleton, cada chamada cria e destrói um client → handshake TCP+TLS
(~100-200ms overhead por request). Com singleton, conexões são reusadas via
keep-alive do connection pool.

Lifecycle: init_http_client() em startup, close_http_client() em shutdown —
mesmo padrão do redis.py.
"""
import httpx

_client: httpx.AsyncClient | None = None


async def init_http_client() -> None:
    """Instancia o client com limites conservadores de pool. Timeout default
    é None — callers sempre passam timeout explícito por request (HIBP e
    Turnstile têm janelas diferentes)."""
    global _client
    _client = httpx.AsyncClient(
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        timeout=None,  # noqa: S113 — callers passam timeout explícito por request
    )


async def close_http_client() -> None:
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def get_http_client() -> httpx.AsyncClient:
    if _client is None:
        raise RuntimeError("HTTP client not initialized — call init_http_client() first")
    return _client
