import asyncio
import contextlib
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

from app.core.database import async_session
from app.core.email import (
    _hash_email,
    send_account_deletion_notification,
    send_new_login_notification,
    send_password_breach_advisory,
    send_password_changed_notification,
    send_password_reset_email,
    send_sessions_terminated_notification,
    send_verification_email,
)
from app.core.redis import get_redis
from app.core.security import (
    create_session,
    delete_all_user_sessions,
    delete_session,
)
from app.core.password_breach import is_password_breached
from app.features.auth.exceptions import (
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidResetTokenError,
    InvalidVerificationTokenError,
    PasswordBreachedError,
    WeakPasswordError,
)
from app.features.auth.models import User
from app.features.auth.rate_limit import (
    check_login_lockout,
    clear_login_failures,
    record_login_failure,
)
from app.features.auth.validators import validate_password

logger = logging.getLogger(__name__)

# Argon2id params explícitos — previne mudança silenciosa em upgrades da lib.
# Baseline OWASP (2024): time_cost≥2, memory_cost≥19 MiB. Aqui subimos para
# 64 MiB de memory_cost — mais resistente a ataques GPU/ASIC. `check_needs_rehash`
# no login upgrade automaticamente quando esses valores forem aumentados.
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,   # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)
_DUMMY_HASH = _ph.hash("dummy-password-for-constant-time-comparison")

_VERIFY_TTL = 86400  # 24 hours
_RESET_TTL = 3600    # 1 hour — token de reset é mais sensível (pode mudar senha)
_SOFT_DELETE_DAYS = 7


# ---------------------------------------------------------------------------
# Background task infrastructure (register-queue pattern)
# ---------------------------------------------------------------------------

# Session scope para workers em background. Module-level para permitir
# monkeypatching em testes (yield da sessão transacional do fixture).
# Produção: sessão nova por task via async_sessionmaker.
@contextlib.asynccontextmanager
async def _default_session_scope():
    async with async_session() as db:
        yield db


_session_scope = _default_session_scope

# Strong references — sem elas, asyncio GC pode matar tasks in-flight antes
# do await completar. Python docs: https://docs.python.org/3/library/asyncio-task.html#creating-tasks
_background_tasks: set[asyncio.Task] = set()


def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verify_token_key(token: str) -> str:
    return f"email_verify:{hashlib.sha256(token.encode()).hexdigest()}"


def _reset_token_key(token: str) -> str:
    """Chave Redis para reset token — hasheada (defense-in-depth igual sessão)."""
    return f"password_reset:{hashlib.sha256(token.encode()).hexdigest()}"


def _known_fingerprints_key(user_id: str) -> str:
    """SET de fingerprints de UA já vistos para esse user. Sem TTL — pequeno
    footprint por usuário (<20 entries típicos), persistente entre logins.
    Primeira fingerprint é silenciosa (evita ruído pós-registro); novas
    fingerprints subsequentes disparam notificação de novo dispositivo."""
    return f"known_fingerprints:{user_id}"


async def _new_device_notification_worker(
    user_id: str, name: str, email: str, ip: str, ua: str,
) -> None:
    """Detecta novo dispositivo via fingerprint do UA estável e dispara email."""
    try:
        from app.core.middleware import _stable_ua
        stable = _stable_ua(ua) if ua else ""
        if not stable:
            return
        fingerprint = hashlib.sha256(stable.encode()).hexdigest()[:16]

        redis = get_redis()
        key = _known_fingerprints_key(user_id)
        # scard + sadd atômico em pipeline (transação), evita race entre
        # dois logins simultâneos do mesmo novo device (só um manda email).
        pipe = redis.pipeline()
        pipe.scard(key)
        pipe.sadd(key, fingerprint)
        existing_count, added = await pipe.execute()

        # Silencia a primeira fingerprint ever (evita notificar logo após
        # register/verify). Notifica só quando user já tinha outros devices.
        if added and existing_count > 0:
            await send_new_login_notification(
                name, email, ip, ua, datetime.now(UTC),
            )
    except Exception:
        logger.exception("New device worker failed user_id=%s", user_id)


async def _sessions_terminated_notification_worker(user_id: str) -> None:
    """Envia notificação de logout global. Fetch user por user_id porque
    caller (logout_all_sessions) só tem o id."""
    try:
        async with _session_scope() as db:
            user = await _get_user_by_id(user_id, db)
            if user is None:
                return
            name, email = user.name, user.email
        await send_sessions_terminated_notification(name, email, datetime.now(UTC))
    except Exception:
        logger.exception(
            "Sessions terminated notification failed user_id=%s", user_id,
        )


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
# Register — register-queue pattern (Auth0/Clerk style)
# ---------------------------------------------------------------------------

async def register_user(
    name: str,
    email: str,
    password: str,
    date_of_birth: date,
) -> None:
    """Handler-side: agenda o worker e retorna.

    Resposta em µs, idêntica para todos os caminhos — elimina o oráculo de
    enumeração por timing (email novo vs existente vs senha breached todos
    retornam igual, porque o handler não toca DB/HIBP/SMTP). Todo o trabalho
    pesado (HIBP, Argon2 hash, DB INSERT, SMTP) vive no worker assíncrono."""
    _spawn(_register_worker(name, email, password, date_of_birth))


async def _register_worker(
    name: str,
    email: str,
    password: str,
    date_of_birth: date,
) -> None:
    """Worker silencioso: falhas (HIBP breach, email duplicado, SMTP down)
    são logadas e engolidas. O cliente já recebeu 202 — qualquer erro aqui
    seria invisível ao cliente (e ao atacante enumerador)."""
    email_hash = _hash_email(email)
    try:
        if await is_password_breached(password):
            logger.info("Register worker: password breached (email_hash=%s)", email_hash)
            return

        password_hash = _ph.hash(password)

        async with _session_scope() as db:
            existing = await _get_user_by_email(email, db, include_deleted=True)
            if existing is not None:
                logger.info("Register worker: email exists (hash=%s)", email_hash)
                return

            user = User(
                name=name,
                email=email,
                password_hash=password_hash,
                date_of_birth=date_of_birth,
            )
            db.add(user)
            await db.flush()

            token = await _create_verification_token(str(user.id), user.email)
            await db.commit()

            # Extrai antes de fechar a sessão — evita lazy-load após close.
            user_name, user_email = user.name, user.email

        # SMTP fora do DB scope: se falhar, usuário pode chamar /resend-verification.
        await send_verification_email(user_name, user_email, token)
    except Exception:
        logger.exception("Register worker failed (email_hash=%s)", email_hash)


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
    raw = await redis.getdel(key)
    if raw is None:
        raise InvalidVerificationTokenError

    data = json.loads(raw)
    user = await _get_user_by_id(data["user_id"], db)
    if user is None:
        raise InvalidVerificationTokenError

    user.is_verified = True
    await db.commit()


async def resend_verification_email(
    email: str, db: AsyncSession, request: Request,
) -> None:
    """Anti-enum: sempre no-op silencioso salvo se user existe + não-verificado."""
    user = await _get_user_by_email(email, db)

    if user is None:
        logger.info("Resend: email inexistente (hash=%s)", _hash_email(email))
        return

    if user.is_verified:
        logger.info("Resend: email já verificado (hash=%s)", _hash_email(email))
        return

    token = await _create_verification_token(str(user.id), user.email)
    _spawn(send_verification_email(user.name, user.email, token))


# ---------------------------------------------------------------------------
# Password reset (esqueci a senha + troca autenticada + aplicar reset)
# ---------------------------------------------------------------------------

async def _create_reset_token(user_id: str) -> str:
    """Emite token opaco one-shot em Redis apontando pro user_id. TTL 1h."""
    token = secrets.token_urlsafe(32)
    data = json.dumps({"user_id": user_id})
    redis = get_redis()
    await redis.set(_reset_token_key(token), data, ex=_RESET_TTL)
    return token


async def _consume_reset_token(token: str) -> str | None:
    """GETDEL atômico — garante uso único mesmo sob concorrência."""
    redis = get_redis()
    raw = await redis.getdel(_reset_token_key(token))
    if raw is None:
        return None
    return json.loads(raw)["user_id"]


async def forgot_password(email: str) -> None:
    """Anti-enum: handler dispara worker e retorna. Worker silencia email
    inexistente ou soft-deleted. Qualquer caminho devolve 202 em µs."""
    _spawn(_forgot_password_worker(email))


async def _forgot_password_worker(email: str) -> None:
    email_hash = _hash_email(email)
    try:
        async with _session_scope() as db:
            user = await _get_user_by_email(email, db)
            if user is None:
                logger.info("Forgot password: email não encontrado (hash=%s)", email_hash)
                return

            user_id = str(user.id)
            name = user.name
            user_email = user.email

        token = await _create_reset_token(user_id)
        await send_password_reset_email(name, user_email, token, flow="forgot")
    except Exception:
        logger.exception("Forgot password worker failed (hash=%s)", email_hash)


async def change_password_request(
    user_id: str, current_password: str, db: AsyncSession,
) -> None:
    """Autenticada: verifica senha atual antes de emitir email de confirmação.
    Proof-of-possession defende contra sequestro de sessão (atacante com cookie
    mas sem senha não consegue disparar a troca)."""
    user = await _get_user_by_id(user_id, db)
    if user is None:
        raise InvalidCredentialsError

    try:
        _ph.verify(user.password_hash, current_password)
    except VerifyMismatchError:
        raise InvalidCredentialsError from None

    _spawn(_change_password_email_worker(user_id))


async def _change_password_email_worker(user_id: str) -> None:
    try:
        async with _session_scope() as db:
            user = await _get_user_by_id(user_id, db)
            if user is None:
                return
            name = user.name
            user_email = user.email

        token = await _create_reset_token(user_id)
        await send_password_reset_email(name, user_email, token, flow="change")
    except Exception:
        logger.exception("Change password email worker failed (user_id=%s)", user_id)


async def reset_password(
    token: str, new_password: str, db: AsyncSession, client_ip: str = "unknown",
) -> None:
    """Aplicação final do reset (sync): consome token, valida nova senha
    (length/entropy/contextual + HIBP), persiste hash, zera flag de breach,
    verifica email (prova de posse), invalida TODAS as sessões existentes.

    Sessões são invalidadas pra forçar re-login em todos os dispositivos —
    se o dispositivo original estava comprometido, ele perde acesso."""
    user_id = await _consume_reset_token(token)
    if user_id is None:
        raise InvalidResetTokenError

    user = await _get_user_by_id(user_id, db)
    if user is None:
        raise InvalidResetTokenError

    try:
        validate_password(new_password, context=[user.name, user.email])
    except ValueError as e:
        raise WeakPasswordError(str(e)) from None

    if await is_password_breached(new_password):
        raise PasswordBreachedError

    user.password_hash = _ph.hash(new_password)
    user.is_verified = True  # clicar no link de reset prova posse do email
    user.password_breach_detected_at = None  # nova senha limpa advisory N-5
    await db.commit()

    # Logout global — sessões antigas não devem sobreviver ao reset
    await delete_all_user_sessions(user_id)

    logger.info(
        "Password reset completed (user_id=%s hash=%s)",
        user_id, _hash_email(user.email),
    )

    # Notificação de senha alterada (out-of-band confirmation).
    _spawn(send_password_changed_notification(
        user.name, user.email, client_ip, datetime.now(UTC),
    ))


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

async def login_user(
    email: str, password: str, db: AsyncSession, request: Request,
) -> tuple[User, str]:
    """Returns (user, session_token). Raises on failure."""
    # Use IP validado via trusted-proxy walk (não o raw client.host)
    from app.core.middleware import get_client_ip
    client_ip = get_client_ip(request)

    # CAPTCHA token opcional — quando presente e válido, bypassa Layer 2
    # (apenas quando CAPTCHA_ENABLED no settings). Header X-Captcha-Token.
    captcha_token = request.headers.get("x-captcha-token")
    captcha_used = await check_login_lockout(
        email, client_ip, captcha_token=captcha_token,
    )

    user = await _get_user_by_email(email, db)

    if user is None:
        # Constant-time: run hash verification even if user doesn't exist
        try:
            _ph.verify(_DUMMY_HASH, password)
        except VerifyMismatchError:
            pass
        await record_login_failure(email, client_ip)
        logger.warning(
            "Login failed: hash=%s ip=%s reason=user_not_found",
            _hash_email(email), client_ip,
        )
        raise InvalidCredentialsError

    try:
        _ph.verify(user.password_hash, password)
    except VerifyMismatchError:
        await record_login_failure(email, client_ip)
        logger.warning(
            "Login failed: hash=%s ip=%s reason=wrong_password",
            _hash_email(email), client_ip,
        )
        raise InvalidCredentialsError from None

    # Password correto. Limpa par (sempre) e global (só se CAPTCHA validado no
    # caminho — atacante com credencial roubada não deve resetar signal de
    # suspeita sem provar "humanidade" via CAPTCHA primeiro).
    await clear_login_failures(email, client_ip, clear_global=captcha_used)

    if not user.is_verified:
        # Only reveal after correct credentials — no enumeration risk
        raise EmailNotVerifiedError

    # Rehash if argon2 params have been upgraded
    if _ph.check_needs_rehash(user.password_hash):
        user.password_hash = _ph.hash(password)
        await db.commit()

    session_token = await create_session(str(user.id), request)

    # N-5: HIBP check contínuo. Só dispara se ainda não detectamos breach
    # para essa conta — evita re-checar a cada login e re-enviar advisory.
    # Flag é limpo quando senha muda (endpoint change-password futuro).
    if user.password_breach_detected_at is None:
        _spawn(_password_breach_check_worker(str(user.id), password))

    # Notificação de novo dispositivo — fingerprint check + email async.
    # Primeira fingerprint por usuário é silenciosa (evita noise pós-register).
    _spawn(_new_device_notification_worker(
        str(user.id), user.name, user.email, client_ip,
        request.headers.get("user-agent", ""),
    ))

    return user, session_token


async def _password_breach_check_worker(user_id: str, password: str) -> None:
    """N-5 worker: consulta HIBP; se vazado, marca user + envia advisory.

    Silencioso — fail-open no HIBP e erros de DB/SMTP logados mas não propagados.
    Login já teve sucesso; este é um nudge de segurança out-of-band."""
    try:
        if not await is_password_breached(password):
            return

        async with _session_scope() as db:
            user = await _get_user_by_id(user_id, db)
            if user is None:
                return
            # Double-check: outra request concorrente já pode ter marcado.
            if user.password_breach_detected_at is not None:
                return

            user.password_breach_detected_at = datetime.now(UTC)
            await db.commit()

            logger.info(
                "Password breach detected for user (hash=%s)",
                _hash_email(user.email),
            )
            user_name, user_email = user.name, user.email

        await send_password_breach_advisory(user_name, user_email)
    except Exception:
        logger.exception("Password breach check worker failed (user_id=%s)", user_id)


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

async def logout_user(token: str) -> None:
    await delete_session(token)


async def logout_all_sessions(user_id: str) -> int:
    count = await delete_all_user_sessions(user_id)
    # Notifica o usuário que todas as sessões foram encerradas (defesa contra
    # sequestro: se alguém rodou logout-all pra "limpar rastros", dono recebe aviso).
    _spawn(_sessions_terminated_notification_worker(user_id))
    return count


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

    deleted_at = datetime.now(UTC)
    user.deleted_at = deleted_at
    await db.commit()
    # NOTA: NÃO chama logout_all_sessions (que dispara notificação de sessões
    # encerradas) — o email de deletion já explica que sessões foram derrubadas.
    # Chamada direta em delete_all_user_sessions evita email duplicado.
    await delete_all_user_sessions(user_id)

    purge_at = deleted_at + timedelta(days=_SOFT_DELETE_DAYS)
    _spawn(send_account_deletion_notification(
        user.name, user.email, deleted_at, purge_at,
    ))


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
