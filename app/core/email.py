import hashlib
import hmac
import logging
from email.message import EmailMessage
from pathlib import Path

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import settings

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates" / "emails"

_jinja_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
    auto_reload=settings.DEBUG,
    enable_async=False,
)

# SMTP header injection guard (RFC 5321 §4.1.1.2)
_FORBIDDEN_HEADER_CHARS = frozenset({"\r", "\n", "\x00"})


# ---------------------------------------------------------------------------
# Low-level
# ---------------------------------------------------------------------------

async def send_email(
    to: str,
    subject: str,
    template_name: str,
    context: dict,
) -> None:
    """Render multipart email (HTML + text) and send via SMTP.

    Renders {template_name}.html (autoescape) + {template_name}.txt (raw)
    from core/templates/emails/. Raises on validation/render/SMTP errors.
    Callers em asyncio.create_task devem capturar exceptions.
    """
    # SMTP injection guard — CRLF/null in headers pode injetar Bcc, etc.
    for field_name, value in (("to", to), ("subject", subject)):
        if any(c in _FORBIDDEN_HEADER_CHARS for c in value):
            raise ValueError(f"Invalid character in {field_name}")

    html_body = _jinja_env.get_template(f"{template_name}.html").render(**context)
    text_body = _jinja_env.get_template(f"{template_name}.txt").render(**context)

    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER or None,
        password=settings.SMTP_PASSWORD or None,
        start_tls=settings.SMTP_TLS,
        timeout=settings.SMTP_TIMEOUT,
    )


# ---------------------------------------------------------------------------
# High-level wrappers (fire-and-forget safe)
# ---------------------------------------------------------------------------

async def send_verification_email(name: str, email: str, token: str) -> None:
    """Safe wrapper para create_task. Captura e loga tudo."""
    link = f"{settings.FRONTEND_URL.rstrip('/')}/verify-email?token={token}"
    try:
        await send_email(
            to=email,
            subject="Confirme seu email",
            template_name="verification",
            context={"name": name, "link": link},
        )
        logger.info("Verification email sent (hash=%s)", _hash_email(email))
    except Exception:
        logger.warning(
            "Failed to send verification email (hash=%s)",
            _hash_email(email),
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# Log hygiene — zero PII
# ---------------------------------------------------------------------------

def _hash_email(email: str) -> str:
    """HMAC-SHA256(SECRET_KEY, email)[:16] — correlaciona logs sem vazar PII.
    Segue o mesmo padrão de core/security.py::generate_csrf_token."""
    return hmac.new(
        settings.SECRET_KEY.encode(),
        email.encode(),
        hashlib.sha256,
    ).hexdigest()[:16]
