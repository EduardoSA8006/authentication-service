import hashlib
import json
import logging
import secrets
from datetime import UTC, date, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import get_redis
from app.core.security import (
    create_session,
    delete_all_user_sessions,
    delete_session,
)
from app.features.auth.exceptions import (
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidVerificationTokenError,
)
from app.features.auth.models import User

logger = logging.getLogger(__name__)

_ph = PasswordHasher()
_DUMMY_HASH = _ph.hash("dummy-password-for-constant-time-comparison")

_VERIFY_TTL = 86400  # 24 hours
_SOFT_DELETE_DAYS = 7


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verify_token_key(token: str) -> str:
    return f"email_verify:{hashlib.sha256(token.encode()).hexdigest()}"


async def _get_user_by_email(
    email: str, db: AsyncSession, *, include_deleted: bool = False,
) -> User | None:
    stmt = select(User).where(User.email == email)
    if not include_deleted:
        stmt = stmt.where(User.deleted_at.is_(None))
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


async def _get_user_by_id(user_id: str, db: AsyncSession) -> User | None:
    stmt = select(User).where(
        User.id == user_id, User.deleted_at.is_(None),
    )
    result = await db.execute(stmt)
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

async def register_user(
    name: str,
    email: str,
    password: str,
    date_of_birth: date,
    db: AsyncSession,
    request: Request,
) -> str | None:
    """Register a new user. Returns verification token or None (anti-enum)."""
    # Always hash to keep constant timing regardless of email existence
    password_hash = _ph.hash(password)

    existing = await _get_user_by_email(email, db, include_deleted=True)
    if existing is not None:
        return None

    user = User(
        name=name,
        email=email,
        password_hash=password_hash,
        date_of_birth=date_of_birth,
    )
    db.add(user)
    await db.flush()

    try:
        token = await _create_verification_token(str(user.id), user.email)
    except Exception:
        await db.rollback()
        raise

    await db.commit()
    return token


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------

async def _create_verification_token(user_id: str, email: str) -> str:
    token = secrets.token_urlsafe(32)
    data = json.dumps({"user_id": user_id, "email": email})
    redis = get_redis()
    await redis.set(_verify_token_key(token), data, ex=_VERIFY_TTL)
    return token


async def verify_email(token: str, db: AsyncSession) -> None:
    redis = get_redis()
    key = _verify_token_key(token)
    raw = await redis.get(key)
    if raw is None:
        raise InvalidVerificationTokenError

    data = json.loads(raw)
    user = await _get_user_by_id(data["user_id"], db)
    if user is None:
        raise InvalidVerificationTokenError

    user.is_verified = True
    await db.commit()
    await redis.delete(key)


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

async def login_user(
    email: str, password: str, db: AsyncSession, request: Request,
) -> tuple[User, str]:
    """Returns (user, session_token). Raises on failure."""
    user = await _get_user_by_email(email, db)

    if user is None:
        # Constant-time: run hash verification even if user doesn't exist
        try:
            _ph.verify(_DUMMY_HASH, password)
        except VerifyMismatchError:
            pass
        raise InvalidCredentialsError

    try:
        _ph.verify(user.password_hash, password)
    except VerifyMismatchError:
        raise InvalidCredentialsError from None

    if not user.is_verified:
        # Only reveal after correct credentials — no enumeration risk
        raise EmailNotVerifiedError

    # Rehash if argon2 params have been upgraded
    if _ph.check_needs_rehash(user.password_hash):
        user.password_hash = _ph.hash(password)
        await db.commit()

    session_token = await create_session(str(user.id), request)
    return user, session_token


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

async def logout_user(token: str) -> None:
    await delete_session(token)


async def logout_all_sessions(user_id: str) -> int:
    return await delete_all_user_sessions(user_id)


# ---------------------------------------------------------------------------
# Get current user
# ---------------------------------------------------------------------------

async def get_user_from_session(session: dict, db: AsyncSession) -> User:
    user = await _get_user_by_id(session["user_id"], db)
    if user is None:
        raise InvalidCredentialsError
    return user


# ---------------------------------------------------------------------------
# Soft delete
# ---------------------------------------------------------------------------

async def soft_delete_user(user_id: str, password: str, db: AsyncSession) -> None:
    user = await _get_user_by_id(user_id, db)
    if user is None:
        raise InvalidCredentialsError

    try:
        _ph.verify(user.password_hash, password)
    except VerifyMismatchError:
        raise InvalidCredentialsError from None

    user.deleted_at = datetime.now(UTC)
    await db.commit()
    await delete_all_user_sessions(user_id)


# ---------------------------------------------------------------------------
# Auto-purge (hard delete after SOFT_DELETE_DAYS)
# ---------------------------------------------------------------------------

async def purge_soft_deleted_users(db: AsyncSession) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=_SOFT_DELETE_DAYS)
    stmt = select(User).where(
        User.deleted_at.is_not(None),
        User.deleted_at < cutoff,
    )
    result = await db.execute(stmt)
    users = result.scalars().all()

    count = 0
    for user in users:
        # Defense-in-depth: ensure no lingering sessions
        await delete_all_user_sessions(str(user.id))
        await db.delete(user)
        count += 1

    if count:
        await db.commit()
        logger.info("Purged %d soft-deleted users", count)

    return count
