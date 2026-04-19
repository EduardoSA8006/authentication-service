"""CAPTCHA verification — step-up pra bypass da Layer 2 do lockout (N-6).

Provider-agnóstico por design; só Turnstile implementado. Adicionar hCaptcha
ou reCAPTCHA é trocar a função `_verify_<provider>` e registrar no dispatch.

Fail-CLOSED: provider down/timeout/erro → False. Assim atacante não pode
derrubar o provider pra bypassar o gate (legítimos ficam bloqueados até o
TTL global expirar; Turnstile tem ~99.99% uptime histórico).
"""
import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


async def verify_captcha(token: str, remote_ip: str) -> bool:
    """True apenas se provider confirmou o token. False em qualquer outro caso
    (token vazio, provider down, resposta malformada, provedor retornou falso)."""
    if not settings.CAPTCHA_ENABLED:
        # Com CAPTCHA desativado, não há bypass. Caller deve tratar como hard-block.
        return False

    if not token or not settings.CAPTCHA_SECRET:
        return False

    provider = settings.CAPTCHA_PROVIDER
    if provider == "turnstile":
        return await _verify_turnstile(token, remote_ip)

    logger.warning("Unknown CAPTCHA provider: %s", provider)
    return False


async def _verify_turnstile(token: str, remote_ip: str) -> bool:
    """Cloudflare Turnstile siteverify endpoint.
    Docs: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
    """
    payload = {
        "secret": settings.CAPTCHA_SECRET,
        "response": token,
        "remoteip": remote_ip,
    }
    try:
        async with httpx.AsyncClient(timeout=settings.CAPTCHA_VERIFY_TIMEOUT) as client:
            r = await client.post(_TURNSTILE_VERIFY_URL, data=payload)
            r.raise_for_status()
            result = r.json()
    except Exception:
        logger.warning("Turnstile verify failed (fail-closed)", exc_info=True)
        return False

    success = bool(result.get("success"))
    if not success:
        logger.info(
            "Turnstile rejected token: %s",
            result.get("error-codes", []),
        )
    return success
