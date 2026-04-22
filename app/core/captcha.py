"""CAPTCHA verification — step-up pra bypass da Layer 2 do lockout (N-6).

Provider-agnóstico por design; só Turnstile implementado. Adicionar hCaptcha
ou reCAPTCHA é trocar a função `_verify_<provider>` e registrar no dispatch.

Fail-CLOSED: provider down/timeout/erro → False. Assim atacante não pode
derrubar o provider pra bypassar o gate (legítimos ficam bloqueados até o
TTL global expirar; Turnstile tem ~99.99% uptime histórico).
"""
import logging

from app.core.config import settings
from app.core.http_client import get_http_client

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


_IP_SENTINELS = frozenset({"invalid", "unknown", ""})


async def _verify_turnstile(token: str, remote_ip: str) -> bool:
    """Cloudflare Turnstile siteverify endpoint.
    Docs: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/

    `remoteip` é opcional no siteverify. Omitimos quando get_client_ip devolve
    sentinel ("invalid"/"unknown") — passá-los faz o provider retornar
    success=false com invalid-parameter, bloqueando vítima legítima atrás de
    proxy mal-configurado do bypass Layer 2.
    """
    payload = {
        "secret": settings.CAPTCHA_SECRET,
        "response": token,
    }
    if remote_ip not in _IP_SENTINELS:
        payload["remoteip"] = remote_ip
    try:
        client = get_http_client()
        r = await client.post(
            _TURNSTILE_VERIFY_URL, data=payload,
            timeout=settings.CAPTCHA_VERIFY_TIMEOUT,
        )
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
