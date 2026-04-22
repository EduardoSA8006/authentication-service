from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "Authentication Service"
    ENVIRONMENT: str = "development"  # "development" | "staging" | "production"
    DEBUG: bool = False

    # PostgreSQL
    POSTGRES_USER: str = "auth"
    POSTGRES_PASSWORD: str = "auth"  # noqa: S105 — dev default; validate_settings bloqueia em prod
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
        if not self.POSTGRES_SSL:
            return base
        if self.POSTGRES_CA_CERT:
            return f"{base}?sslmode=verify-full&sslrootcert={self.POSTGRES_CA_CERT}"
        # Sem CA explícita: libpq usa system CA bundle por padrão. verify-full
        # ainda valida hostname contra CN/SAN — verify-ca sozinho permitiria
        # MitM com cert válido emitido por qualquer CA do bundle.
        return f"{base}?sslmode=verify-full"

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
    MINIO_SECRET_KEY: str = "minioadmin"  # noqa: S105 — dev default; validate_settings bloqueia em prod
    MINIO_SECURE: bool = False

    # Security
    SECRET_KEY: str  # Required — no default, must be set in .env
    ALLOWED_ORIGINS: list[str] = ["http://localhost:3000"]
    ALLOWED_HOSTS: list[str]  # Required — no default
    TRUSTED_PROXY_IPS: list[str] = ["127.0.0.1", "::1"]
    POSTGRES_SSL: bool = False
    POSTGRES_CA_CERT: str = ""           # path to CA bundle; obrigatório se POSTGRES_SSL
    REDIS_TLS: bool = False
    REDIS_CA_CERT: str = ""              # path to CA bundle; opcional (rediss:// usa system CAs)
    HIBP_ENABLED: bool = True            # checa senha contra HaveIBeenPwned via k-anonymity
    HIBP_TIMEOUT: float = 3.0            # fail-open após timeout
    # Email de contato opcional incluído no User-Agent do HIBP. HIBP docs
    # recomendam contact info pra que abuse-detection da Cloudflare consiga
    # contatar operador antes de bloquear. Vazio = UA genérico, ainda válido
    # mas risco de bloqueio silencioso sob volume alto.
    HIBP_CONTACT: str = ""

    # Argon2id parallelism. Default 4 assume host/container com 4+ cores
    # dedicados. Em k8s com CPU request=1 ou VPS 2-core, parallelism=4 não
    # ganha nada e pode degradar por contention — ajustar pra `os.cpu_count()`
    # do deploy target. Mudanças em produção disparam rehash no próximo login
    # de cada usuário (check_needs_rehash), custo único distribuído.
    ARGON2_PARALLELISM: int = 4

    # CAPTCHA — step-up quando Layer 2 do lockout dispara (N-6 integration).
    # Default True: sem CAPTCHA o Layer 2 vira hard-block de 30min sem bypass
    # para usuário legítimo sob credential stuffing distribuído. Em produção,
    # validate_settings_for_production bloqueia startup se ENABLED=False.
    CAPTCHA_ENABLED: bool = True
    CAPTCHA_PROVIDER: str = "turnstile"  # "turnstile" (Cloudflare); futuro: hcaptcha/recaptcha
    CAPTCHA_SECRET: str = ""             # server-side secret do provider
    CAPTCHA_SITE_KEY: str = ""           # public, frontend usa pra renderizar widget
    CAPTCHA_VERIFY_TIMEOUT: float = 5.0

    # Email / SMTP — TLS vem em dois sabores:
    #   SMTP_TLS=true, SMTP_IMPLICIT_TLS=false → STARTTLS (porta 587, padrão
    #     da maioria dos provedores modernos: Gmail, Outlook corporate,
    #     Postmark, Mailgun)
    #   SMTP_TLS=false, SMTP_IMPLICIT_TLS=true → SMTPS (TLS implícito na
    #     porta 465, requerido por SES/SendGrid em alguns tiers e tooling
    #     legacy)
    # Os dois flags são mutuamente exclusivos: validate_settings bloqueia
    # combinação inválida.
    SMTP_HOST: str = "mailhog"
    SMTP_PORT: int = 1025
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_TLS: bool = False            # STARTTLS (porta 587)
    SMTP_IMPLICIT_TLS: bool = False   # SMTPS (porta 465)
    SMTP_FROM: str = "Authentication Service <noreply@localhost>"
    # 10s cobre jitter normal de relays (Mailgun/SES/Postmark p99 < 3s); 15s
    # permitia backlog quando o relay estava lento — com retry exponencial
    # (3 tentativas) em N logins concorrentes, o drain de shutdown (10s)
    # extrapola. Operador em relay reconhecidamente lento pode subir via .env.
    SMTP_TIMEOUT: int = 10  # segundos

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
        return self.ENVIRONMENT == "production"

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

_INSECURE_SECRET = "change-me-in-production-use-a-random-64-char-string"  # noqa: S105 — placeholder pra detectar que SECRET_KEY não foi trocado
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
    elif not settings.POSTGRES_CA_CERT:
        warnings.append(
            "POSTGRES_SSL is True but POSTGRES_CA_CERT is empty — "
            "certificate validated against system CAs only (no custom CA pinning)"
        )

    if not settings.REDIS_TLS:
        warnings.append("REDIS_TLS is False — Redis connection is unencrypted")
    elif not settings.REDIS_CA_CERT:
        warnings.append(
            "REDIS_TLS is True but REDIS_CA_CERT is empty — "
            "certificate validated against system CAs only (no custom CA pinning)"
        )

    if not settings.HIBP_ENABLED:
        warnings.append(
            "HIBP_ENABLED is False — passwords not checked against breach database"
        )

    if not settings.CAPTCHA_ENABLED:
        warnings.append(
            "CAPTCHA_ENABLED is False — Layer 2 lockout will hard-block suspected "
            "credential stuffing (no step-up bypass for legitimate users)"
        )
    elif not settings.CAPTCHA_SECRET:
        warnings.append(
            "CAPTCHA_ENABLED is True but CAPTCHA_SECRET is empty — verify calls "
            "will fail-closed, locking out users during suspicious activity"
        )

    if settings.FRONTEND_URL.startswith("http://"):
        warnings.append("FRONTEND_URL uses http:// (not https://)")

    if "localhost" in settings.FRONTEND_URL:
        warnings.append("FRONTEND_URL contains 'localhost'")

    if settings.SMTP_HOST in {"mailhog", "localhost"}:
        warnings.append(f"SMTP_HOST is '{settings.SMTP_HOST}' — dev-only")

    if not settings.SMTP_TLS and not settings.SMTP_IMPLICIT_TLS:
        warnings.append(
            "SMTP_TLS and SMTP_IMPLICIT_TLS both False — email sent in plaintext",
        )

    if settings.SMTP_TLS and settings.SMTP_IMPLICIT_TLS:
        warnings.append(
            "SMTP_TLS and SMTP_IMPLICIT_TLS both True — escolha um: STARTTLS "
            "(587) ou SMTPS implícito (465), não os dois",
        )

    if not settings.SMTP_PASSWORD:
        warnings.append("SMTP_PASSWORD is empty")

    if not settings.ALLOWED_HOSTS:
        # Lista vazia = TrustedHostMiddleware rejeita TUDO (fail-closed,
        # bom pra segurança). Mas em produção com config assim o serviço
        # não responde nada — quase certamente misconfig.
        warnings.append(
            "ALLOWED_HOSTS is empty — TrustedHostMiddleware rejeitará "
            "todos os requests",
        )

    if "localhost" in settings.ALLOWED_HOSTS:
        warnings.append("ALLOWED_HOSTS contains 'localhost'")

    if "*" in settings.ALLOWED_HOSTS:
        warnings.append("ALLOWED_HOSTS contains wildcard '*'")

    if "*" in settings.ALLOWED_ORIGINS:
        warnings.append("ALLOWED_ORIGINS contains wildcard '*'")

    if not settings.TRUSTED_PROXY_IPS:
        warnings.append(
            "TRUSTED_PROXY_IPS is empty — XFF will always be ignored. "
            "If service is behind a reverse proxy, add its IP"
        )

    # COOKIE_DOMAIN deve ser sufixo do host de FRONTEND_URL — senão cookies
    # não são enviados pelo browser. Validação de formato completa (sem
    # scheme, sem espaços, sintaxe DNS válida) não é feita aqui: Starlette
    # falha com erro explícito ao tentar setar um cookie com valor inválido.
    # O teste de sufixo cobre o erro de config mais comum.
    if settings.COOKIE_DOMAIN:
        from urllib.parse import urlparse
        fe_host = (urlparse(settings.FRONTEND_URL).hostname or "").lower()
        cookie_dom = settings.COOKIE_DOMAIN.lstrip(".").lower()
        if cookie_dom and fe_host and not fe_host.endswith(cookie_dom):
            warnings.append(
                f"COOKIE_DOMAIN='{settings.COOKIE_DOMAIN}' não é sufixo do "
                f"FRONTEND_URL host='{fe_host}' — browser não enviará cookies"
            )

    _MAX_SESSION_TTL = 30 * 86400  # 30 dias
    if settings.SESSION_TTL > _MAX_SESSION_TTL:
        days = settings.SESSION_TTL // 86400
        warnings.append(
            f"SESSION_TTL={days} days (>30) — sessões longas aumentam janela "
            "de hijack; provavelmente não intencional"
        )

    if settings.SESSION_IDLE_TTL > settings.SESSION_TTL:
        warnings.append(
            "SESSION_IDLE_TTL > SESSION_TTL — TTL absoluto sempre vence, "
            "idle TTL é inútil. Verifique a configuração"
        )

    return warnings
