from app.core.exceptions import (
    BadRequestError,
    ForbiddenError,
    NotFoundError,
    RateLimitedError,
    UnauthorizedError,
)


class InvalidCredentialsError(UnauthorizedError):
    code = "INVALID_CREDENTIALS"
    message = "Credenciais inválidas"


class SessionExpiredError(UnauthorizedError):
    code = "SESSION_EXPIRED"
    message = "Sessão expirada"


class EmailNotVerifiedError(ForbiddenError):
    code = "EMAIL_NOT_VERIFIED"
    message = "Email não verificado"


class InvalidVerificationTokenError(BadRequestError):
    code = "INVALID_VERIFICATION_TOKEN"
    message = "Token de verificação inválido ou expirado"


class PasswordBreachedError(BadRequestError):
    code = "PASSWORD_BREACHED"
    message = "Esta senha apareceu em vazamento conhecido — escolha outra"


class InvalidResetTokenError(BadRequestError):
    code = "INVALID_RESET_TOKEN"
    message = "Token de redefinição inválido ou expirado"


class WeakPasswordError(BadRequestError):
    code = "WEAK_PASSWORD"
    message = "Senha não atende os requisitos mínimos"


class SuspiciousActivityError(RateLimitedError):
    """N-6: camada 2 de lockout (contador global por email). Dispara quando
    um email recebe muitas falhas distribuídas (IP rotation) e sugere que
    um ataque de credential stuffing está em andamento.

    Frontend deve renderizar widget CAPTCHA (Turnstile/etc) e re-enviar o
    request com header `X-Captcha-Token` — backend bypassa Layer 2 se o
    token for validado contra o provider."""
    code = "SUSPICIOUS_ACTIVITY"
    message = "Atividade suspeita detectada. Verificação adicional necessária."


class CaptchaInvalidError(BadRequestError):
    """Token CAPTCHA foi submetido mas o provider rejeitou (expirado, reusado,
    malformado, hostname errado). Frontend deve obter token fresco do widget."""
    code = "CAPTCHA_INVALID"
    message = "Verificação CAPTCHA inválida — gere um novo token"


class SessionNotFoundError(NotFoundError):
    """Session alvo não existe OU não pertence ao caller. Unificamos os dois
    casos no mesmo 404 — expor 403 ("não é sua") vs 404 ("não existe") criaria
    oráculo pra enumerar session_ids de outros usuários."""
    code = "SESSION_NOT_FOUND"
    message = "Sessão não encontrada"


class InvalidSessionIdError(BadRequestError):
    """session_id no path não passou no formato esperado (64 hex chars)."""
    code = "INVALID_SESSION_ID"
    message = "session_id inválido"
