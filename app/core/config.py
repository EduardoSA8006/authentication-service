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
        return (
            f"postgresql+psycopg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # Redis
    REDIS_HOST: str = "redis"
    REDIS_PORT: int = 6379
    REDIS_PASSWORD: str = ""

    @property
    def redis_url(self) -> str:
        cred = f":{self.REDIS_PASSWORD}@" if self.REDIS_PASSWORD else ""
        return f"redis://{cred}{self.REDIS_HOST}:{self.REDIS_PORT}/0"

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

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

_INSECURE_SECRET = "change-me-in-production-use-a-random-64-char-string"
_MIN_SECRET_LENGTH = 32


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

    if "localhost" in settings.ALLOWED_HOSTS:
        warnings.append("ALLOWED_HOSTS contains 'localhost'")

    if "*" in settings.ALLOWED_HOSTS:
        warnings.append("ALLOWED_HOSTS contains wildcard '*'")

    if "*" in settings.ALLOWED_ORIGINS:
        warnings.append("ALLOWED_ORIGINS contains wildcard '*'")

    return warnings
