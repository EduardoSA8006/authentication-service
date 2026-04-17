from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Authentication Service"
    ENVIRONMENT: str = "development"  # "development" | "production"
    DEBUG: bool = False

    # PostgreSQL
    POSTGRES_USER: str = "auth"
    POSTGRES_PASSWORD: str = "auth"
    POSTGRES_DB: str = "auth_service"
    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    DB_ECHO: bool = False

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    @property
    def database_url_sync(self) -> str:
        base = (
            f"postgresql+psycopg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
        return f"{base}?sslmode=require" if self.POSTGRES_SSL else base

    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""
    REDIS_DB: int = 0

    @property
    def redis_url(self) -> str:
        scheme = "rediss" if self.REDIS_TLS else "redis"
        cred = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"{scheme}://{cred}{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    # MinIO
    MINIO_ENDPOINT: str = "minio:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_SECURE: bool = False

    # Security
    SECRET_KEY: str  # Required — no default, must be set in .env
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000"]
    ALLOWED_HOSTS: list[str]  # Required — no default
    TRUSTED_PROXY_IPS: list[str] = ["127.0.0.1", "::1"]
    POSTGRES_SSL: bool = False
    REDIS_TLS: bool = False

    # Email / SMTP
    SMTP_HOST: str = "mailhog"
    SMTP_PORT: int = 1025
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_TLS: bool = False
    SMTP_FROM: str = "Authentication Service <noreply@localhost>"
    SMTP_TIMEOUT: int = 15  # segundos

    # Frontend URL (obrigatório — sem default; Pydantic falha se ausente)
    FRONTEND_URL: str

    # Rate limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60

    # Request size (bytes)
    MAX_REQUEST_SIZE: int = 10_485_760

    # Session / Cookies
    SESSION_COOKIE_NAME: str = "session"
    CSRF_COOKIE_NAME: str = "csrf_token"
    CSRF_HEADER_NAME: str = "x-csrf-token"
    COOKIE_DOMAIN: str | None = None
    COOKIE_SECURE: bool = False
    COOKIE_PATH: str = "/"
    SESSION_TTL: int = 604800
    SESSION_IDLE_TTL: int = 86400
    TOKEN_ROTATION_INTERVAL: int = 3600
    TOKEN_ROTATION_GRACE: int = 60

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT != "development"

    @property
    def session_cookie(self) -> str:
        if self.COOKIE_SECURE and not self.COOKIE_DOMAIN and self.COOKIE_PATH == "/":
            return f"__Host-{self.SESSION_COOKIE_NAME}"
        return self.SESSION_COOKIE_NAME

    @property
    def csrf_cookie(self) -> str:
        if self.COOKIE_SECURE and not self.COOKIE_DOMAIN and self.COOKIE_PATH == "/":
            return f"__Host-{self.CSRF_COOKIE_NAME}"
        return self.CSRF_COOKIE_NAME

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

_INSECURE_SECRET = "change-me-in-production-use-a-random-64-char-string"
_MIN_SECRET_LENGTH = 32
_MIN_SERVICE_PASSWORD_LENGTH = 12
_INSECURE_DEFAULTS = frozenset({
    "auth", "redis", "minioadmin", "password", "secret",
    "admin", "root", "test", "123456", "postgres",
})


def validate_settings_for_production() -> list[str]:
    """Return security warnings. Every item here blocks startup outside development."""
    warnings: list[str] = []

    if settings.DEBUG:
        warnings.append("DEBUG is True")

    if settings.SECRET_KEY == _INSECURE_SECRET:
        warnings.append("SECRET_KEY still has the placeholder value")

    if len(settings.SECRET_KEY) < _MIN_SECRET_LENGTH:
        warnings.append(
            f"SECRET_KEY is too short ({len(settings.SECRET_KEY)} chars, "
            f"minimum {_MIN_SECRET_LENGTH})"
        )

    if not settings.COOKIE_SECURE:
        warnings.append("COOKIE_SECURE is False")

    if not settings.MINIO_SECURE:
        warnings.append("MINIO_SECURE is False")

    if not settings.REDIS_PASSWORD:
        warnings.append("REDIS_PASSWORD is empty")
    elif settings.REDIS_PASSWORD.lower() in _INSECURE_DEFAULTS:
        warnings.append("REDIS_PASSWORD uses a known default value")

    if settings.POSTGRES_PASSWORD.lower() in _INSECURE_DEFAULTS:
        warnings.append("POSTGRES_PASSWORD uses a known default value")

    if len(settings.POSTGRES_PASSWORD) < _MIN_SERVICE_PASSWORD_LENGTH:
        warnings.append(
            f"POSTGRES_PASSWORD is too short ({len(settings.POSTGRES_PASSWORD)} chars, "
            f"minimum {_MIN_SERVICE_PASSWORD_LENGTH})"
        )

    if settings.MINIO_ACCESS_KEY.lower() in _INSECURE_DEFAULTS:
        warnings.append("MINIO_ACCESS_KEY uses a known default value")

    if settings.MINIO_SECRET_KEY.lower() in _INSECURE_DEFAULTS:
        warnings.append("MINIO_SECRET_KEY uses a known default value")

    if not settings.POSTGRES_SSL:
        warnings.append("POSTGRES_SSL is False — database connection is unencrypted")

    if not settings.REDIS_TLS:
        warnings.append("REDIS_TLS is False — Redis connection is unencrypted")

    if settings.FRONTEND_URL.startswith("http://"):
        warnings.append("FRONTEND_URL uses http:// (not https://)")

    if "localhost" in settings.FRONTEND_URL:
        warnings.append("FRONTEND_URL contains 'localhost'")

    if settings.SMTP_HOST in {"mailhog", "localhost"}:
        warnings.append(f"SMTP_HOST is '{settings.SMTP_HOST}' — dev-only")

    if not settings.SMTP_TLS:
        warnings.append("SMTP_TLS is False — email sent in plaintext")

    if not settings.SMTP_PASSWORD:
        warnings.append("SMTP_PASSWORD is empty")

    if "localhost" in settings.ALLOWED_HOSTS:
        warnings.append("ALLOWED_HOSTS contains 'localhost'")

    if "*" in settings.ALLOWED_HOSTS:
        warnings.append("ALLOWED_HOSTS contains wildcard '*'")

    if "*" in settings.ALLOWED_ORIGINS:
        warnings.append("ALLOWED_ORIGINS contains wildcard '*'")

    return warnings
