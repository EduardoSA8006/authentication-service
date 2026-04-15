"""
Exception hierarchy.

    AppError                       ← base (all custom errors inherit from this)
    ├── NotFoundError              404
    ├── UnauthorizedError          401
    ├── ForbiddenError             403
    ├── BadRequestError            400
    ├── ConflictError              409
    ├── RateLimitedError           429
    └── (feature exceptions)       ← each feature extends AppError
        e.g. features/auth/exceptions.py → InvalidCredentialsError

Usage in routes / services:
    raise NotFoundError("User not found")
    raise ConflictError("Email already taken", details={"field": "email"})
"""


class AppError(Exception):
    status_code: int = 500
    code: str = "INTERNAL_ERROR"
    message: str = "Internal server error"
    headers: dict[str, str] | None = None

    def __init__(
        self,
        message: str | None = None,
        *,
        details: dict | list | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.message = message or self.__class__.message
        self.details = details
        self.headers = headers or self.__class__.headers
        super().__init__(self.message)


# ---------------------------------------------------------------------------
# 4xx
# ---------------------------------------------------------------------------

class BadRequestError(AppError):
    status_code = 400
    code = "BAD_REQUEST"
    message = "Bad request"


class UnauthorizedError(AppError):
    status_code = 401
    code = "UNAUTHORIZED"
    message = "Not authenticated"


class ForbiddenError(AppError):
    status_code = 403
    code = "FORBIDDEN"
    message = "Access denied"


class NotFoundError(AppError):
    status_code = 404
    code = "NOT_FOUND"
    message = "Resource not found"


class ConflictError(AppError):
    status_code = 409
    code = "CONFLICT"
    message = "Resource conflict"


class RateLimitedError(AppError):
    status_code = 429
    code = "RATE_LIMITED"
    message = "Too many requests"


# ---------------------------------------------------------------------------
# 5xx
# ---------------------------------------------------------------------------

class ServiceUnavailableError(AppError):
    status_code = 503
    code = "SERVICE_UNAVAILABLE"
    message = "Service temporarily unavailable"
