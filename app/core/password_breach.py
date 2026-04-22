"""Checa senhas contra HaveIBeenPwned Pwned Passwords via k-anonymity.

Protocolo: envia só os 5 primeiros chars do SHA-1 (hex) da senha. A API
retorna todos os sufixos de hashes que começam com esse prefixo (bucket
de ~500-1000 hashes). Comparamos localmente — zero vazamento da senha.

Docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""
import hashlib
import logging

from app.core.config import settings
from app.core.http_client import get_http_client

logger = logging.getLogger(__name__)

_HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def _user_agent() -> str:
    """UA seguindo recomendação HIBP: identifica app + contato opcional. Sem
    contato, abuse-detection da Cloudflare pode bloquear sem aviso. Operador
    que ignorar o setting fica com UA genérico (comportamento anterior)."""
    base = "authentication-service-breach-check"
    if settings.HIBP_CONTACT:
        return f"{base} <{settings.HIBP_CONTACT}>"
    return base


def sha1_prefix_suffix(password: str) -> tuple[str, str]:
    """Retorna (prefix, suffix) uppercase de SHA-1(password). Split em 5+35
    chars é o contrato k-anonymity do HIBP. Exposto pra callers que queiram
    descartar o plaintext imediatamente e só passar o hash-split adiante
    (reduz plaintext-lifetime em workers async)."""
    sha1 = hashlib.sha1(password.encode(), usedforsecurity=False).hexdigest().upper()
    return sha1[:5], sha1[5:]


async def is_sha1_breached(prefix: str, suffix: str) -> bool:
    """Mesma consulta k-anonymity de is_password_breached, mas recebe o SHA-1
    pré-computado pelo caller. Útil em background workers que não precisam
    mais do plaintext — evita que a senha fique viva no frame da coroutine
    até o await completar (janela inspecionável via core dump / proc memory).

    Fail-open em erro de rede, mesmo contrato da variante high-level."""
    if not settings.HIBP_ENABLED:
        return False

    try:
        client = get_http_client()
        r = await client.get(
            _HIBP_URL.format(prefix=prefix),
            headers={"User-Agent": _user_agent()},
            timeout=settings.HIBP_TIMEOUT,
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


async def is_password_breached(password: str) -> bool:
    """True se senha foi vista em vazamento conhecido.

    Fail-open: erros de rede/timeout → False + log warning. Disponibilidade
    do serviço de auth não pode depender de API externa estar up.

    Desabilitado via HIBP_ENABLED=false (dev/test).
    """
    if not settings.HIBP_ENABLED:
        return False

    prefix, suffix = sha1_prefix_suffix(password)
    return await is_sha1_breached(prefix, suffix)
