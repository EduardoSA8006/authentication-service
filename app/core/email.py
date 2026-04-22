import logging
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from typing import Literal

import aiosmtplib
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import settings
from app.core.security import hash_email

logger = logging.getLogger(__name__)

_TEMPLATE_DIR = Path(__file__).parent / "templates" / "emails"

_jinja_env = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    autoescape=select_autoescape(["html"]),
    auto_reload=settings.DEBUG,
    # enable_async: render_async não bloqueia o event loop. Impacto é pequeno
    # em templates simples, mas o padrão correto em código async.
    enable_async=True,
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

    html_body = await _jinja_env.get_template(f"{template_name}.html").render_async(**context)
    text_body = await _jinja_env.get_template(f"{template_name}.txt").render_async(**context)

    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")

    # STARTTLS (start_tls) e SMTPS implícito (use_tls) são mutuamente
    # exclusivos em aiosmtplib: use_tls abre o socket já em TLS (porta 465);
    # start_tls upgrada plain → TLS via STARTTLS command (porta 587).
    #
    # validate_certs=True é explícito (default da lib já é True, mas fixar
    # aqui evita regressão se alguém copiar kwargs pra outro call-site que
    # mude o default via tls_context customizado). Self-signed em dev
    # precisa de override consciente — fail-loud antes, não silencioso.
    await aiosmtplib.send(
        msg,
        hostname=settings.SMTP_HOST,
        port=settings.SMTP_PORT,
        username=settings.SMTP_USER or None,
        password=settings.SMTP_PASSWORD or None,
        start_tls=settings.SMTP_TLS,
        use_tls=settings.SMTP_IMPLICIT_TLS,
        validate_certs=True,
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
        logger.info("Verification email sent (hash=%s)", hash_email(email))
    except Exception:
        logger.warning(
            "Failed to send verification email (hash=%s)",
            hash_email(email),
            exc_info=True,
        )


async def send_password_reset_email(
    name: str,
    email: str,
    token: str,
    flow: Literal["forgot", "change"],
) -> None:
    """Link de redefinição de senha. `flow` seleciona copy e subject:
    - 'forgot': usuário anônimo pediu reset (esqueceu senha)
    - 'change': usuário autenticado pediu troca (re-autenticação via email)."""
    link = f"{settings.FRONTEND_URL.rstrip('/')}/reset-password?token={token}"
    if flow == "forgot":
        subject = "Redefinição de senha"
        template = "password_reset_forgot"
    else:
        subject = "Confirme a troca de senha"
        template = "password_reset_change"
    try:
        await send_email(
            to=email,
            subject=subject,
            template_name=template,
            context={"name": name, "link": link},
        )
        logger.info(
            "Password reset email sent (hash=%s flow=%s)",
            hash_email(email), flow,
        )
    except Exception:
        logger.warning(
            "Failed to send password reset email (hash=%s flow=%s)",
            hash_email(email), flow,
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# Security event notifications — fire-and-forget
# ---------------------------------------------------------------------------

_MAX_TEMPLATE_FIELD = 256


def _truncate_for_template(value: str, max_len: int = _MAX_TEMPLATE_FIELD) -> str:
    """Corta strings que vão pro contexto de email. UA pode vir com 10KB+ de
    lixo (extensões, strings de debug, payloads de ataque); IP cru pode ter
    qualquer coisa que o caller passe. Autoescape do Jinja protege de XSS,
    mas sem truncagem o email final vira gigante (email gateways rejeitam)
    e o conteúdo visível fica ilegível. 256 chars cobre UAs legítimos."""
    if value is None:
        return ""
    s = str(value)
    if len(s) <= max_len:
        return s
    return s[: max_len - 1] + "…"


def _ua_summary(ua: str) -> str:
    """Heurística simples pra resumir User-Agent em "Browser em OS" legível.
    Não é 100% accurate (UA strings são inconsistentes), mas suficiente para
    email de notificação. Evita dependência externa de ua-parser."""
    if not ua:
        return "dispositivo desconhecido"

    if "Firefox/" in ua:
        browser = "Firefox"
    elif "Edg/" in ua:
        browser = "Edge"
    elif "OPR/" in ua or "Opera" in ua:
        browser = "Opera"
    elif "Chrome/" in ua:
        browser = "Chrome"
    elif "Safari/" in ua:
        browser = "Safari"
    else:
        browser = "navegador desconhecido"

    # iOS primeiro: iPhone UA contém "Mac OS X" (Apple faz isso pra compat).
    if "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Android" in ua:
        os_name = "Android"
    elif "Windows" in ua:
        os_name = "Windows"
    elif "Mac OS X" in ua or "Macintosh" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "sistema desconhecido"

    return f"{browser} em {os_name}"


def _fmt_when(dt: datetime) -> str:
    return dt.strftime("%d/%m/%Y %H:%M UTC")


def _reset_link() -> str:
    return f"{settings.FRONTEND_URL.rstrip('/')}/settings/password"


async def send_new_login_notification(
    name: str, email: str, ip: str, user_agent: str, when: datetime,
) -> None:
    """Notifica quando login chega de um novo dispositivo (novo fingerprint)."""
    try:
        await send_email(
            to=email,
            subject="Novo dispositivo acessou sua conta",
            template_name="new_login_notification",
            context={
                "name": name,
                # Truncagem defensiva: UA pode vir inflado (extensões, debug
                # strings) e IP é controlado parcialmente pelo header path.
                # Autoescape já cobre XSS; limite protege tamanho final do email.
                "ip": _truncate_for_template(ip),
                "device": _truncate_for_template(_ua_summary(user_agent)),
                "when": _fmt_when(when),
                "reset_link": _reset_link(),
            },
        )
        logger.info("New login notification sent (hash=%s)", hash_email(email))
    except Exception:
        logger.warning(
            "Failed to send new login notification (hash=%s)",
            hash_email(email), exc_info=True,
        )


async def send_password_changed_notification(
    name: str, email: str, ip: str, when: datetime,
) -> None:
    """Notifica quando senha foi trocada via reset flow."""
    try:
        await send_email(
            to=email,
            subject="Sua senha foi alterada",
            template_name="password_changed_notification",
            context={
                "name": name,
                "ip": _truncate_for_template(ip),
                "when": _fmt_when(when),
            },
        )
        logger.info("Password changed notification sent (hash=%s)", hash_email(email))
    except Exception:
        logger.warning(
            "Failed to send password changed notification (hash=%s)",
            hash_email(email), exc_info=True,
        )


async def send_account_deletion_notification(
    name: str, email: str, when: datetime, purge_at: datetime,
) -> None:
    """Notifica quando conta foi marcada pra soft delete (grace 7 dias)."""
    try:
        await send_email(
            to=email,
            subject="Conta agendada para exclusão",
            template_name="account_deletion_scheduled",
            context={
                "name": name,
                "when": _fmt_when(when),
                "purge_at": _fmt_when(purge_at),
            },
        )
        logger.info("Account deletion notification sent (hash=%s)", hash_email(email))
    except Exception:
        logger.warning(
            "Failed to send account deletion notification (hash=%s)",
            hash_email(email), exc_info=True,
        )


async def send_sessions_terminated_notification(
    name: str, email: str, when: datetime,
) -> None:
    """Notifica quando todas as sessões foram encerradas (logout-all ou reset)."""
    try:
        await send_email(
            to=email,
            subject="Todas as sessões foram encerradas",
            template_name="sessions_terminated_notification",
            context={
                "name": name,
                "when": _fmt_when(when),
                "reset_link": _reset_link(),
            },
        )
        logger.info(
            "Sessions terminated notification sent (hash=%s)", hash_email(email),
        )
    except Exception:
        logger.warning(
            "Failed to send sessions terminated notification (hash=%s)",
            hash_email(email), exc_info=True,
        )


async def send_password_breach_advisory(name: str, email: str) -> None:
    """N-5: notifica usuário que sua senha apareceu em breach público (HIBP).
    Nudge suave — conta permanece ativa. Link aponta pra /settings/password."""
    link = f"{settings.FRONTEND_URL.rstrip('/')}/settings/password"
    try:
        await send_email(
            to=email,
            subject="Sua senha pode estar comprometida",
            template_name="password_breach_advisory",
            context={"name": name, "link": link},
        )
        logger.info("Password breach advisory sent (hash=%s)", hash_email(email))
    except Exception:
        logger.warning(
            "Failed to send password breach advisory (hash=%s)",
            hash_email(email),
            exc_info=True,
        )

