import asyncio
import contextlib
import hashlib
import json
import logging
import secrets
from datetime import UTC, date, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import async_session
from app.core.email import (
    _ua_summary,
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
    delete_session_by_id,
    hash_email,
    ip_subnet,
    is_valid_session_id,
    list_user_sessions,
    stable_ua,
)
from app.core.password_breach import (
    is_password_breached,
    is_sha1_breached,
    sha1_prefix_suffix,
)
from app.features.auth.exceptions import (
    EmailNotVerifiedError,
    InvalidCredentialsError,
    InvalidResetTokenError,
    InvalidSessionIdError,
    InvalidVerificationTokenError,
    PasswordBreachedError,
    SessionNotFoundError,
    WeakPasswordError,
)
from app.features.auth.models import User
from app.features.auth.rate_limit import (
    check_login_lockout,
    clear_login_failures,
    record_login_failure,
)
from app.features.auth.validators import validate_password


# Erros do Argon2 que devem virar InvalidCredentialsError (401), não 500:
# - VerifyMismatchError: senha errada (caso normal).
# - InvalidHashError: hash corrompido no DB (migração mal-feita, truncamento,
#   backup-restore incompleto). 500 cria oráculo: "corrupção" distinguível de
#   "senha errada". Unificar em 401 impede esse side-channel e evita vazar
#   stack trace com estado interno.
# - VerificationError: erro genérico de hasher (edge cases, timeout). Mesmo
#   tratamento defensivo — prefere 401 consistente a 500 com detalhes.
_PASSWORD_VERIFY_ERRORS = (
    VerifyMismatchError, InvalidHashError, VerificationError,
)

logger = logging.getLogger(__name__)

# Argon2id params explícitos — previne mudança silenciosa em upgrades da lib.
# Baseline OWASP (2024): time_cost≥2, memory_cost≥19 MiB. Aqui subimos para
# 64 MiB de memory_cost — mais resistente a ataques GPU/ASIC. `check_needs_rehash`
# no login upgrade automaticamente quando esses valores forem aumentados.
#
# CUIDADO COM DOWNGRADE: baixar params aqui faz todo login válido disparar
# rehash (senha correta, mas hash "mais forte" do que params atuais →
# check_needs_rehash=True → _ph.hash() extra no hot path). DoS auto-infligido
# sem ganho de segurança. Quando houver métricas, monitorar contador de
# rehash_per_login: pico súbito = alguém baixou os params sem querer.
_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,   # 64 MiB
    parallelism=settings.ARGON2_PARALLELISM,
    hash_len=32,
    salt_len=16,
)

# _DUMMY_HASH é gerado com esses params (~100-500ms por ser Argon2id pesado).
# Computar em import-time bloqueia startup em ambientes sensíveis (serverless
# cold start, pytest discovery). Lazy-init no primeiro uso.
_DUMMY_HASH: str | None = None


def _get_dummy_hash() -> str:
    """Hash dummy para verificação constant-time quando user não existe.

    Regenera automaticamente se os params do _ph mudarem (upgrade de memory_cost,
    time_cost, etc). Sem isso, dummy ficaria com params antigos enquanto hashes
    reais rodariam com params novos → timing drift detectável entre
    'user inexistente' vs 'user existente' (oráculo de enumeração).

    check_needs_rehash retorna True quando o hash foi gerado com params
    diferentes dos atuais do _ph; trata isso como sinal pra regenerar."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None or _ph.check_needs_rehash(_DUMMY_HASH):
        _DUMMY_HASH = _ph.hash("dummy-password-for-constant-time-comparison")
    return _DUMMY_HASH


async def warmup_password_hasher() -> None:
    """Computa _DUMMY_HASH antecipadamente no startup. Sem isso, o primeiro
    login com email inexistente depois do cold-start paga ~300-500ms extras
    de Argon2id dentro do event loop — amplia janela de timing para enumeração
    (user válido responde rápido; user desconhecido no primeiro hit responde
    devagar, distinguível). asyncio.to_thread porque Argon2id é CPU-bound e
    bloqueia o loop se rodar direto."""
    await asyncio.to_thread(_get_dummy_hash)

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


def _spawn(coro, *, label: str = "unlabeled") -> asyncio.Task:
    """Enfileira task in-memory com label pra observability.

    Limitação: tasks são in-process — se o pod crashar (SIGKILL, OOM) entre
    o 202 e o completion, o trabalho é PERDIDO sem retry. Graceful shutdown
    (SIGTERM → lifespan drain) cobre restart normal; crash hard requer fila
    durável (ARQ/Celery/Postgres-backed) — out of scope nesta camada.

    O label é logado em spawn/done pra facilitar correlação em incident
    response: se logs mostram "Scheduled register_worker:hash=X" mas nenhum
    "Completed register_worker:hash=X", operador sabe que perdeu essa unit
    e pode reprocessar manualmente a partir do contexto."""
    task = asyncio.create_task(coro, name=label)
    _background_tasks.add(task)

    def _on_done(t: asyncio.Task) -> None:
        _background_tasks.discard(t)
        if t.cancelled():
            logger.warning("Background task cancelled: %s", label)
            return
        exc = t.exception()
        if exc is not None:
            # Worker interno já faz logger.exception; duplicar aqui ajuda
            # operador a ver o label mesmo sem ler o stack completo.
            logger.error(
                "Background task failed: %s (%s)", label, type(exc).__name__,
            )
        else:
            logger.debug("Background task completed: %s", label)

    task.add_done_callback(_on_done)
    logger.info("Background task scheduled: %s", label)
    return task


async def drain_background_tasks(timeout: float) -> int:
    """Aguarda tasks pendentes completarem durante shutdown. Retorna o número
    de tasks que NÃO completaram no timeout — operador deve reprocessar
    manualmente (logs têm o label de cada task via _spawn).

    Usa asyncio.wait (não wait_for) pra evitar que o timeout CANCELE as tasks:
    queremos só esperar com limite e reportar quais ficaram pendentes, não
    matar trabalho a meio caminho.

    Chamado no lifespan antes de close_redis/close_http_client pra evitar
    workers in-flight baterem em conexões já fechadas."""
    tasks = [t for t in _background_tasks if not t.done()]
    if not tasks:
        return 0
    _, pending = await asyncio.wait(tasks, timeout=timeout)
    for t in pending:
        logger.error(
            "Background task did not drain in %.1fs: %s",
            timeout, t.get_name(),
        )
    return len(pending)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verify_token_key(token: str) -> str:
    return f"email_verify:{hashlib.sha256(token.encode()).hexdigest()}"


def _verify_token_user_key(user_id: str) -> str:
    """Ponteiro user → token_key corrente. Garante one-token-per-user:
    emitir novo verify invalida o anterior (N-8 — previne reaproveitamento de
    link antigo em caso de MitM SMTP/inbox comprometido)."""
    return f"email_verify_user:{user_id}"


def _reset_token_key(token: str) -> str:
    """Chave Redis para reset token — hasheada (defense-in-depth igual sessão)."""
    return f"password_reset:{hashlib.sha256(token.encode()).hexdigest()}"


def _reset_token_user_key(user_id: str) -> str:
    """Ponteiro user → token_key corrente para reset. Mesma motivação do
    verify: novo token invalida anterior atomicamente (Lua)."""
    return f"password_reset_user:{user_id}"


# Lua: emite token novo invalidando anterior atomicamente — tanto do mesmo
# tipo (one-token-per-user) quanto do tipo cruzado (verify ↔ reset).
#
# Motivação da invalidação cruzada: verify-email e reset-password provam a
# mesma coisa (posse do inbox). Se os dois canais coexistem, um vazamento
# em qualquer um dos dois (MitM SMTP, inbox comprometido) ainda permite
# tomar o outro. Emitir um invalida o outro (padrão Auth0/Clerk).
#
# KEYS[1] = user pointer do tipo emitido (ex: email_verify_user:uid)
# KEYS[2] = novo token key (ex: email_verify:<hash>)
# KEYS[3] = user pointer do tipo cruzado (ex: password_reset_user:uid)
# ARGV[1] = payload JSON
# ARGV[2] = TTL segundos
_LUA_ISSUE_SINGLE_TOKEN = """\
local old = redis.call('GET', KEYS[1])
if old and old ~= KEYS[2] then
    redis.call('DEL', old)
end
local cross = redis.call('GET', KEYS[3])
if cross then
    redis.call('DEL', cross)
    redis.call('DEL', KEYS[3])
end
redis.call('SET', KEYS[2], ARGV[1], 'EX', ARGV[2])
redis.call('SET', KEYS[1], KEYS[2], 'EX', ARGV[2])
"""  # noqa: S105 — script Lua, não é senha


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
        stable = stable_ua(ua) if ua else ""
        if not stable:
            return
        fingerprint = hashlib.sha256(stable.encode()).hexdigest()[:16]

        redis = get_redis()
        key = _known_fingerprints_key(user_id)
        # scard + sadd atômico em pipeline (transação), evita race entre
        # dois logins simultâneos do mesmo novo device (só um manda email).
        pipe = redis.pipeline(transaction=True)
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


def _ip_change_dedup_key(user_id: str, subnet: str) -> str:
    """Dedup cross-session: usuário logado em 2+ devices não recebe N emails
    quando a rede muda. TTL 1h cobre reconexão de VPN/mobile sem re-spammar."""
    return f"ip_change_notified:{user_id}:{subnet}"


_IP_CHANGE_DEDUP_TTL = 3600

# Retry policy para email transacional em workers críticos (register). SMTP
# é falho por natureza (DNS flap, connection reset, rate-limit do relay);
# 3 tentativas com backoff exponencial cobrem ~95% das falhas transientes
# sem prender o worker indefinidamente. Total máximo ~7s (1 + 2 + 4) + latência
# do SMTP. Workers de notificação menos críticos podem fazer single-shot.
_EMAIL_RETRY_ATTEMPTS = 3
_EMAIL_RETRY_BACKOFF_BASE = 1.0


async def _send_email_with_retry(
    send_coro_factory, *, label: str,
) -> bool:
    """Chama send_coro_factory() (lambda que retorna coroutine fresca a cada
    tentativa) com backoff exponencial. Retorna True se conseguiu enviar,
    False se esgotou tentativas. Não relança — caller decide o que fazer.

    Requer factory (não coroutine pronta) porque uma coroutine só pode ser
    awaited uma vez; passar o objeto reusa e raises RuntimeError na 2ª try."""
    for attempt in range(1, _EMAIL_RETRY_ATTEMPTS + 1):
        try:
            await send_coro_factory()
            if attempt > 1:
                logger.info("Email sent on retry %d: %s", attempt, label)
            return True
        except Exception:
            if attempt == _EMAIL_RETRY_ATTEMPTS:
                logger.exception(
                    "Email delivery failed after %d attempts: %s",
                    attempt, label,
                )
                return False
            wait = _EMAIL_RETRY_BACKOFF_BASE * (2 ** (attempt - 1))
            logger.warning(
                "Email delivery attempt %d failed for %s — retrying in %.1fs",
                attempt, label, wait,
            )
            await asyncio.sleep(wait)
    return False


async def _ip_change_notification_worker(
    user_id: str, new_ip: str, ua: str,
) -> None:
    """Notifica mudança de subnet (/24 IPv4 ou /48 IPv6) na sessão existente.
    NÃO quebra a sessão — usuários mobile/VPN trocam de rede legitimamente.
    O sinal serve só pra incident response: vítima de cookie theft vê o email
    e troca a senha, invalidando todas as sessões via reset."""
    try:
        subnet = ip_subnet(new_ip)
        if subnet is None:
            return

        redis = get_redis()
        # SET NX com TTL — dedup atômico. Primeiro worker wins, resto silencia.
        acquired = await redis.set(
            _ip_change_dedup_key(user_id, subnet),
            "1", nx=True, ex=_IP_CHANGE_DEDUP_TTL,
        )
        if not acquired:
            return

        async with _session_scope() as db:
            user = await _get_user_by_id(user_id, db)
            if user is None:
                return
            name, email = user.name, user.email

        await send_new_login_notification(
            name, email, new_ip, ua, datetime.now(UTC),
        )
    except Exception:
        logger.exception("IP change worker failed user_id=%s", user_id)


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
    _spawn(
        _register_worker(name, email, password, date_of_birth),
        label=f"register_worker:hash={hash_email(email)}",
    )


async def _register_worker(
    name: str,
    email: str,
    password: str,
    date_of_birth: date,
) -> None:
    """Worker silencioso: falhas (HIBP breach, email duplicado, SMTP down)
    são logadas e engolidas. O cliente já recebeu 202 — qualquer erro aqui
    seria invisível ao cliente (e ao atacante enumerador)."""
    email_hash = hash_email(email)
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

            token = await _create_verification_token(str(user.id))
            await db.commit()

            # Extrai antes de fechar a sessão — evita lazy-load após close.
            user_name, user_email = user.name, user.email

        # SMTP fora do DB scope. Retry exponencial cobre flap transiente
        # (DNS, connection reset, relay rate-limit). Se todas falharem, log
        # escalado + /resend-verification continua disponível como fallback
        # manual do usuário. Trade-off: conta fica criada sem email até o
        # user notar e pedir resend — preferível a rollback que apagaria o
        # usuário e complicaria recuperação.
        sent = await _send_email_with_retry(
            lambda: send_verification_email(user_name, user_email, token),
            label=f"verification_email:hash={email_hash}",
        )
        if not sent:
            logger.error(
                "Register completed but verification email undelivered "
                "(email_hash=%s) — user precisa chamar /resend-verification",
                email_hash,
            )
    except Exception:
        logger.exception("Register worker failed (email_hash=%s)", email_hash)


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------

_issue_token_script = None


def _get_issue_token_script():
    """Lazy-register Lua script; redis-py cacheia SHA1 e usa EVALSHA."""
    global _issue_token_script
    if _issue_token_script is None:
        _issue_token_script = get_redis().register_script(_LUA_ISSUE_SINGLE_TOKEN)
    return _issue_token_script


async def _create_verification_token(user_id: str) -> str:
    """Payload do token guarda SÓ user_id — não o email. Se Redis vazar
    (dump, sniffing em replica, misconfig de backup), o atacante só tem
    UUIDs opacos; email fica só no Postgres, sob controle de acesso
    separado. Reduz o raio de PII em Redis (mesma abordagem do reset token).

    Invalida atomicamente qualquer reset token pendente do mesmo usuário
    (KEYS[3]): verify e reset provam a mesma coisa (posse do inbox), então
    emitir um mata o outro pra fechar janela de MitM cruzado."""
    token = secrets.token_urlsafe(32)
    data = json.dumps({"user_id": user_id})
    script = _get_issue_token_script()
    await script(
        keys=[
            _verify_token_user_key(user_id),
            _verify_token_key(token),
            _reset_token_user_key(user_id),
        ],
        args=[data, str(_VERIFY_TTL)],
    )
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

    # Limpa o ponteiro user → token (consumo one-shot; sobra só o TTL do ponteiro).
    await redis.delete(_verify_token_user_key(data["user_id"]))

    user.is_verified = True
    await db.commit()


async def resend_verification_email(email: str) -> None:
    """Anti-enum: spawna worker e retorna em µs — latência idêntica para
    email inexistente, já-verificado, ou não-verificado."""
    _spawn(
        _resend_verification_worker(email),
        label=f"resend_verification:hash={hash_email(email)}",
    )


async def _resend_verification_worker(email: str) -> None:
    email_hash = hash_email(email)
    try:
        async with _session_scope() as db:
            user = await _get_user_by_email(email, db)
            if user is None:
                logger.info("Resend: email inexistente (hash=%s)", email_hash)
                return
            if user.is_verified:
                logger.info("Resend: email já verificado (hash=%s)", email_hash)
                return
            token = await _create_verification_token(str(user.id))
            user_name, user_email = user.name, user.email
        await send_verification_email(user_name, user_email, token)
    except Exception:
        logger.exception("Resend verification worker failed (hash=%s)", email_hash)


# ---------------------------------------------------------------------------
# Password reset (esqueci a senha + troca autenticada + aplicar reset)
# ---------------------------------------------------------------------------

async def _create_reset_token(user_id: str) -> str:
    """Emite token opaco one-shot em Redis apontando pro user_id. TTL 1h.

    Invalida atomicamente via Lua:
    - token de reset anterior (one-token-per-user — evita 3 cliques em
      "esqueci a senha" resultarem em 3 tokens simultâneos aproveitáveis);
    - token de verify-email pendente (KEYS[3]) — verify e reset provam a
      mesma coisa (posse do inbox), então emitir um mata o outro."""
    token = secrets.token_urlsafe(32)
    data = json.dumps({"user_id": user_id})
    script = _get_issue_token_script()
    await script(
        keys=[
            _reset_token_user_key(user_id),
            _reset_token_key(token),
            _verify_token_user_key(user_id),
        ],
        args=[data, str(_RESET_TTL)],
    )
    return token


async def _consume_reset_token(token: str) -> str | None:
    """GETDEL atômico — garante uso único mesmo sob concorrência. Também
    limpa o ponteiro user → token (não é estritamente necessário; ele expira
    pelo TTL e é sobrescrito em nova emissão, mas remove rastro imediato)."""
    redis = get_redis()
    raw = await redis.getdel(_reset_token_key(token))
    if raw is None:
        return None
    user_id = json.loads(raw)["user_id"]
    await redis.delete(_reset_token_user_key(user_id))
    return user_id


async def forgot_password(email: str) -> None:
    """Anti-enum: handler dispara worker e retorna. Worker silencia email
    inexistente ou soft-deleted. Qualquer caminho devolve 202 em µs."""
    _spawn(
        _forgot_password_worker(email),
        label=f"forgot_password:hash={hash_email(email)}",
    )


async def _forgot_password_worker(email: str) -> None:
    email_hash = hash_email(email)
    try:
        async with _session_scope() as db:
            user = await _get_user_by_email(email, db)
            if user is None:
                logger.info("Forgot password: email não encontrado (hash=%s)", email_hash)
                return

            # Recusa silenciosa para contas não verificadas: reset-email é porta
            # lateral que probaria posse do inbox sem passar pelo fluxo dedicado
            # de verify-email (TTL 24h + HMAC-SHA256). Atacante podia registrar
            # com email alheio e acionar /forgot-password para entregar token de
            # reset ao dono legítimo; a verificação tem de vir pelo canal próprio.
            if not user.is_verified:
                logger.info(
                    "Forgot password: conta não verificada (hash=%s)", email_hash,
                )
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
    except _PASSWORD_VERIFY_ERRORS:
        raise InvalidCredentialsError from None

    _spawn(
        _change_password_email_worker(user_id),
        label=f"change_password_email:user_id={user_id}",
    )


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

    # Revoga sessões ANTES do commit. Se Redis falhar, a exceção propaga e o
    # commit não roda — mudanças em `user` ficam descartadas na unit-of-work.
    # Inverso (commit antes) cria desync: nova senha ativa + cookies antigos
    # válidos até SESSION_TTL (7 dias), mantendo acesso de atacante/device.
    await delete_all_user_sessions(user_id)
    await db.commit()

    logger.info(
        "Password reset completed (user_id=%s hash=%s)",
        user_id, hash_email(user.email),
    )

    # Notificação de senha alterada (out-of-band confirmation).
    _spawn(
        send_password_changed_notification(
            user.name, user.email, client_ip, datetime.now(UTC),
        ),
        label=f"password_changed_notification:user_id={user_id}",
    )


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

async def login_user(
    email: str,
    password: str,
    db: AsyncSession,
    *,
    ip: str,
    user_agent: str,
    captcha_token: str | None = None,
) -> tuple[User, str]:
    """Returns (user, session_token). Raises on failure.

    Todos os dados de transporte (IP já resolvido via get_client_ip, user-agent,
    captcha_token) chegam como parâmetros — o serviço não conhece Request/HTTP.
    O router é responsável pela extração."""
    captcha_used = await check_login_lockout(
        email, ip, captcha_token=captcha_token,
    )

    user = await _get_user_by_email(email, db)

    if user is None:
        # Constant-time: run hash verification even if user doesn't exist
        try:
            _ph.verify(_get_dummy_hash(), password)
        except _PASSWORD_VERIFY_ERRORS:
            pass
        await record_login_failure(email, ip)
        logger.warning(
            "Login failed: hash=%s ip_subnet=%s reason=user_not_found",
            hash_email(email), ip_subnet(ip) or ip,
        )
        raise InvalidCredentialsError

    try:
        _ph.verify(user.password_hash, password)
    except _PASSWORD_VERIFY_ERRORS:
        await record_login_failure(email, ip)
        logger.warning(
            "Login failed: hash=%s ip_subnet=%s reason=wrong_password",
            hash_email(email), ip_subnet(ip) or ip,
        )
        raise InvalidCredentialsError from None

    # Password correto. Limpa par (sempre) e global (só se CAPTCHA validado no
    # caminho — atacante com credencial roubada não deve resetar signal de
    # suspeita sem provar "humanidade" via CAPTCHA primeiro).
    await clear_login_failures(email, ip, clear_global=captcha_used)

    if not user.is_verified:
        # Only reveal after correct credentials — no enumeration risk
        raise EmailNotVerifiedError

    # Rehash if argon2 params have been upgraded.
    #
    # TODO(observability): quando houver backend de métricas, instrumentar
    # counter `argon2_rehash_per_login` incrementado aqui. Upgrade de params
    # (ex: memory_cost 64→128 MiB) faz todo login válido pagar _ph.hash extra
    # (~300-600ms) até a base rehashar; sem métrica, degradação de latência
    # no p99 vira mistério em incident response. Comentário em _ph acima
    # também menciona esse hot-path.
    if _ph.check_needs_rehash(user.password_hash):
        user.password_hash = _ph.hash(password)
        await db.commit()

    session_token = await create_session(
        str(user.id), ip=ip, user_agent=user_agent,
    )

    # N-5: HIBP check contínuo. Só dispara se ainda não detectamos breach
    # para essa conta — evita re-checar a cada login e re-enviar advisory.
    # Flag é limpo quando senha muda (endpoint change-password futuro).
    #
    # Computa SHA-1 síncrono AQUI e só passa (prefix, suffix) ao worker —
    # a senha plaintext não sobrevive a essa linha no frame da task async.
    # Reduz plaintext-lifetime (inspecionável via core dump / gdb attach)
    # de "até o worker completar" para microssegundos do hash.
    if user.password_breach_detected_at is None:
        prefix, suffix = sha1_prefix_suffix(password)
        _spawn(
            _password_breach_check_worker(str(user.id), prefix, suffix),
            label=f"password_breach_check:user_id={user.id}",
        )

    # Notificação de novo dispositivo — fingerprint check + email async.
    # Primeira fingerprint por usuário é silenciosa (evita noise pós-register).
    _spawn(
        _new_device_notification_worker(
            str(user.id), user.name, user.email, ip, user_agent,
        ),
        label=f"new_device_notification:user_id={user.id}",
    )

    return user, session_token


async def _password_breach_check_worker(
    user_id: str, sha1_prefix: str, sha1_suffix: str,
) -> None:
    """N-5 worker: consulta HIBP com SHA-1 pré-computado; se vazado, marca
    user + envia advisory. Worker NUNCA recebe plaintext — se o processo
    for inspecionado (core dump, proc memory), só o hash está em memória.

    Silencioso — fail-open no HIBP e erros de DB/SMTP logados mas não propagados.
    Login já teve sucesso; este é um nudge de segurança out-of-band."""
    try:
        if not await is_sha1_breached(sha1_prefix, sha1_suffix):
            return

        async with _session_scope() as db:
            user = await _get_user_by_id(user_id, db)
            if user is None:
                return
            user_name, user_email = user.name, user.email

            # UPDATE atômico: só marca se ainda estiver NULL. Substitui o
            # check-then-set que tinha TOCTOU (dois logins concorrentes com
            # senha breached ambos passavam pelo `is None` check → 2 commits
            # → 2 emails). rowcount==1 ⇒ vencemos a corrida, send advisory.
            # rowcount==0 ⇒ outra request já marcou, silencia.
            stmt = (
                update(User)
                .where(
                    User.id == user_id,
                    User.password_breach_detected_at.is_(None),
                )
                .values(password_breach_detected_at=datetime.now(UTC))
                # synchronize_session="fetch" invalida o User na identity map
                # da sessão — sem isso, um select(User) subsequente via ORM
                # devolveria o objeto cacheado com a coluna ainda NULL.
                .execution_options(synchronize_session="fetch")
            )
            result = await db.execute(stmt)
            await db.commit()
            if result.rowcount != 1:
                return

            logger.info(
                "Password breach detected for user (hash=%s)",
                hash_email(user_email),
            )

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
    _spawn(
        _sessions_terminated_notification_worker(user_id),
        label=f"sessions_terminated_notification:user_id={user_id}",
    )
    return count


# ---------------------------------------------------------------------------
# Session management (listar / revogar específica)
# ---------------------------------------------------------------------------

async def list_active_sessions(
    user_id: str, current_session_id: str | None,
) -> list[dict]:
    """Monta payload público da listagem. Filtra grace (ver list_user_sessions)
    e reduz os campos da sessão pra evitar vazamento de PII:

    - session_id: hash SHA256 do token (opaco, estável, não-revertível).
    - created_at / last_active: timestamps ISO8601 pra UI de "último acesso".
    - ip_prefix: só /24 IPv4 ou /48 IPv6; endereço completo fica no backend.
    - device: resumo "Browser em OS" via _ua_summary; nunca o UA bruto
      (UA pode conter build IDs, extensões, versões precisas — fingerprintable).
    - is_current: marca a sessão do request atual, pra UI poder destacar."""
    raw_sessions = await list_user_sessions(user_id)
    out: list[dict] = []
    for s in raw_sessions:
        sid = s.get("session_id", "")
        out.append({
            "session_id": sid,
            "created_at": s["created_at"],
            "last_active": s["last_active"],
            "ip_prefix": ip_subnet(s.get("ip", "")),
            "device": _ua_summary(s.get("user_agent", "")),
            "is_current": sid == current_session_id,
        })
    return out


async def revoke_session(user_id: str, session_id: str) -> None:
    """Revoga sessão específica do próprio usuário. Erros:
    - InvalidSessionIdError (400) — session_id malformado (antes do Redis).
    - SessionNotFoundError (404) — sessão inexistente OU de outro usuário.
      404 unificado evita oráculo pra enumerar IDs de sessões alheias."""
    if not is_valid_session_id(session_id):
        raise InvalidSessionIdError
    deleted = await delete_session_by_id(user_id, session_id)
    if not deleted:
        raise SessionNotFoundError


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
    except _PASSWORD_VERIFY_ERRORS:
        raise InvalidCredentialsError from None

    deleted_at = datetime.now(UTC)
    user.deleted_at = deleted_at

    # Revoga sessões ANTES do commit. Se Redis falhar, `deleted_at` não
    # persiste — evita desync onde user fica marcado como deletado mas ainda
    # com cookies válidos em dispositivos ativos. Defense-in-depth adicional:
    # _get_user_by_id já filtra deleted_at IS NULL, mas middlewares que usam
    # só dados da sessão (sem fetch no DB) não veriam a exclusão.
    # NOTA: NÃO chama logout_all_sessions (que dispara notificação de sessões
    # encerradas) — o email de deletion já explica que sessões foram derrubadas.
    # Chamada direta em delete_all_user_sessions evita email duplicado.
    await delete_all_user_sessions(user_id)
    await db.commit()

    purge_at = deleted_at + timedelta(days=_SOFT_DELETE_DAYS)
    _spawn(
        send_account_deletion_notification(
            user.name, user.email, deleted_at, purge_at,
        ),
        label=f"account_deletion_notification:user_id={user_id}",
    )


# ---------------------------------------------------------------------------
# Auto-purge (hard delete after SOFT_DELETE_DAYS)
# ---------------------------------------------------------------------------

async def purge_soft_deleted_users(db: AsyncSession) -> int:
    cutoff = datetime.now(UTC) - timedelta(days=_SOFT_DELETE_DAYS)
    # Só carrega IDs — evita materializar objetos User inteiros em memória
    # quando há muitos users para purgar.
    id_stmt = select(User.id).where(
        User.deleted_at.is_not(None),
        User.deleted_at < cutoff,
    )
    result = await db.execute(id_stmt)
    user_ids = list(result.scalars())

    if not user_ids:
        return 0

    # Defense-in-depth: cleanup de sessões Redis por user (não-bulk; chaves
    # estão por user_id individual).
    for uid in user_ids:
        await delete_all_user_sessions(str(uid))

    # Bulk DELETE — uma única query no DB em vez de N DELETEs individuais.
    await db.execute(delete(User).where(User.id.in_(user_ids)))
    await db.commit()

    count = len(user_ids)
    logger.info("Purged %d soft-deleted users", count)
    return count
