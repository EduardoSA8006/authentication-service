# MUST be at the very top — before any app.* import
import os
from pathlib import Path

_env_file = Path(__file__).parent / ".env.test"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        stripped = line.strip()
        if "=" in stripped and not stripped.startswith("#"):
            k, v = stripped.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"'))


# Imports depois do loader — garante que Settings lê env correto
import asyncio  # noqa: E402
from datetime import date  # noqa: E402

import httpx  # noqa: E402
import pytest_asyncio  # noqa: E402
from argon2 import PasswordHasher  # noqa: E402
from httpx import ASGITransport  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from app.core.database import engine, get_db  # noqa: E402
from app.core.redis import close_redis, get_redis, init_redis  # noqa: E402
from app.features.auth.models import User  # noqa: E402
from app.main import app  # noqa: E402
from tests.helpers.mailhog import MailHog  # noqa: E402


# ---------------------------------------------------------------------------
# Serviços compartilhados (session scope)
# pytest-asyncio 0.26+ gerencia event loop via config; não customizar fixture.
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="session", autouse=True)
async def _services():
    await init_redis()
    yield
    await close_redis()


# ---------------------------------------------------------------------------
# Isolamento por teste
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def db():
    """Transacional — ROLLBACK no teardown."""
    async with engine.connect() as conn:
        trans = await conn.begin()
        async with AsyncSession(
            bind=conn,
            join_transaction_mode="create_savepoint",
            expire_on_commit=False,
        ) as session:
            yield session
        await trans.rollback()


@pytest_asyncio.fixture(autouse=True)
async def _clean_redis():
    redis = get_redis()
    await redis.flushdb()
    yield


@pytest_asyncio.fixture(autouse=True)
async def _gather_pending_tasks():
    """Coleta tasks pendentes (send_verification_email em background)."""
    yield
    pending = [
        t for t in asyncio.all_tasks()
        if t is not asyncio.current_task() and not t.done()
    ]
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(db):
    async def _override_db():
        yield db

    app.dependency_overrides[get_db] = _override_db
    async with httpx.AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"Origin": "http://localhost:3000"},
    ) as c:
        yield c
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------

_ph = PasswordHasher()


@pytest_asyncio.fixture
async def make_user(db):
    async def _make(
        email: str = "test@example.com",
        password: str = "SenhaForte@2026",
        name: str = "João Silva",
        verified: bool = True,
        **overrides,
    ) -> User:
        user = User(
            name=name,
            email=email,
            password_hash=_ph.hash(password),
            date_of_birth=overrides.pop("date_of_birth", date(1990, 1, 1)),
            is_verified=verified,
            **overrides,
        )
        db.add(user)
        await db.flush()
        return user

    return _make


# ---------------------------------------------------------------------------
# Helpers de autenticação
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def logged_in_client(client, make_user):
    """Retorna (user, client) com sessão + header CSRF já setados."""
    user = await make_user(email="loggedin@test.com", password="SenhaForte@2026")
    r = await client.post("/auth/login", json={
        "email": "loggedin@test.com",
        "password": "SenhaForte@2026",
    })
    assert r.status_code == 200, r.text
    csrf = r.cookies.get("csrf_token")
    client.headers["X-CSRF-Token"] = csrf
    return user, client


# ---------------------------------------------------------------------------
# MailHog
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def mailhog():
    m = MailHog()
    await m.clear()
    yield m
    await m.clear()
