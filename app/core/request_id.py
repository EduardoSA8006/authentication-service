"""Correlation ID por request para rastreabilidade em incident response.

Fluxo:
  1. RequestIDMiddleware gera UUID (ou aproveita X-Request-ID recebido)
  2. Valor vai pro contextvar _request_id_var
  3. RequestIDFilter injeta no LogRecord como attr request_id
  4. Formatter inclui %(request_id)s nos logs
  5. Response ecoa X-Request-ID pro cliente
"""
import logging
import uuid
from contextvars import ContextVar

_request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

# UUID recebido de cliente não deve ser arbitrariamente longo nem conter CRLF
# (injection em header de log). 64 chars hex é suficiente pra UUID4 + margem.
_MAX_LEN = 64


def new_request_id() -> str:
    return uuid.uuid4().hex


def get_request_id() -> str | None:
    return _request_id_var.get()


def set_request_id(value: str) -> None:
    _request_id_var.set(value)


_HEX_CHARS = frozenset("0123456789abcdef")


def sanitize_request_id(value: str) -> str:
    """Aceita X-Request-ID do cliente mas sanitiza para formato interno
    (hex-only, igual ao new_request_id via uuid4().hex). Caracteres não-hex
    são descartados — evita log injection (CRLF) e mantém formato único
    entre IDs gerados internamente e IDs ecoados do cliente."""
    cleaned = "".join(c for c in value.lower() if c in _HEX_CHARS)[:_MAX_LEN]
    return cleaned or new_request_id()


class RequestIDFilter(logging.Filter):
    """Injeta request_id do contextvar em cada LogRecord.
    Usa '-' quando fora de uma request (startup, background tasks)."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id_var.get() or "-"
        return True
