"""Checa senhas contra HaveIBeenPwned Pwned Passwords via k-anonymity.

Protocolo: envia só os 5 primeiros chars do SHA-1 (hex) da senha. A API
retorna todos os sufixos de hashes que começam com esse prefixo (bucket
de ~500-1000 hashes). Comparamos localmente — zero vazamento da senha.

Docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""
import hashlib
import logging

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

_HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"


async def is_password_breached(password: str) -> bool:
    """True se senha foi vista em vazamento conhecido.

    Fail-open: erros de rede/timeout → False + log warning. Disponibilidade
    do serviço de auth não pode depender de API externa estar up.

    Desabilitado via HIBP_ENABLED=false (dev/test).
    """
    if not settings.HIBP_ENABLED:
        return False

    sha1 = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        async with httpx.AsyncClient(timeout=settings.HIBP_TIMEOUT) as client:
            r = await client.get(
                _HIBP_URL.format(prefix=prefix),
                headers={"User-Agent": "authentication-service-breach-check"},
            )
            r.raise_for_status()
    except Exception:
        logger.warning("HIBP check unavailable, allowing password (fail-open)")
        return False

    for line in r.text.splitlines():
        hash_suffix, _, _count = line.partition(":")
        if hash_suffix.strip().upper() == suffix:
            return True
    return False
