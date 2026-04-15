from app.core.exceptions import BadRequestError, ForbiddenError, UnauthorizedError


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


class AccountDeletedError(UnauthorizedError):
    code = "ACCOUNT_DELETED"
    message = "Credenciais inválidas"
