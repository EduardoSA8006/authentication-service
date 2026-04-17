import ssl

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


def _build_ssl_context() -> ssl.SSLContext:
    """SSLContext com verify-full (hostname + CA validation).
    Sem isso, ssl='require' apenas criptografa sem validar certificado — MITM possível."""
    if settings.POSTGRES_CA_CERT:
        ctx = ssl.create_default_context(cafile=settings.POSTGRES_CA_CERT)
    else:
        # Sem CA explícita — usa system CA bundle
        ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


_connect_args: dict = {}
if settings.POSTGRES_SSL:
    _connect_args["ssl"] = _build_ssl_context()

engine = create_async_engine(
    settings.database_url,
    echo=settings.DB_ECHO,
    pool_size=10,
    max_overflow=5,
    pool_timeout=30,
    pool_recycle=1800,
    connect_args=_connect_args,
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with async_session() as session:
        yield session
