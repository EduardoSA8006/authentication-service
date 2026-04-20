import hashlib
import hmac
import json
import re
import secrets
from datetime import UTC, datetime

from fastapi import Request, Response

from app.core.config import settings
from app.core.redis import get_redis

_TOKEN_BYTES = 36  # 36 bytes → exactly 48 chars in base64url

_UA_VERSIONS = re.compile(r"\d+\.\d+[\d.]*")


def _stable_ua(ua: str) -> str:
    """Strip version numbers from UA for resilient session binding.

    NOTA DE SEGURANÇA: UA binding NÃO é defesa séria — qualquer atacante forja
    User-Agent trivialmente. Este check só protege contra vetores triviais
    (ex: extensão maliciosa que rouba cookie mas mantém UA default do Chrome)."""
    return _UA_VERSIONS.sub("*", ua)


def hash_email(email: str) -> str:
    """HMAC-SHA256(SECRET_KEY, email)[:16] — correlaciona logs sem vazar PII."""
    return hmac.new(
        settings.SECRET_KEY.encode(),
        email.encode(),
        hashlib.sha256,
    ).hexdigest()[:16]

# Lua script for atomic invalidation of all sessions for a user.
# Reads the set, deletes every session key, then deletes the set itself.
# This runs atomically inside Redis — no TOCTOU race.
_LUA_DELETE_ALL = """
local set_key = KEYS[1]
local members = redis.call('SMEMBERS', set_key)
for _, k in ipairs(members) do
    redis.call('DEL', k)
end
redis.call('DEL', set_key)
return #members
"""

# Atomic touch (N-7): re-lê o estado em Redis antes de sobrescrever, pra
# fechar o TOCTOU entre get_session (caller) e o SET que refresh o TTL.
# Se outra request rotacionou essa chave pra grace entre um e outro, o SET
# não dispara — grace e seu TTL curto são preservados.
#
# Retorna 1 se touch ocorreu, 0 se foi no-op (key deleted, grace, ou JSON inválido).
_LUA_TOUCH = """
local current = redis.call('GET', KEYS[1])
if not current then
    return 0
end
local ok, parsed = pcall(cjson.decode, current)
if not ok then
    return 0
end
if parsed.grace then
    return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
return 1
"""


# ---------------------------------------------------------------------------
# Token generation
# ---------------------------------------------------------------------------

def generate_session_token() -> str:
    return secrets.token_urlsafe(_TOKEN_BYTES)


def _session_key(token: str) -> str:
    """Hash the token before using as Redis key (defense-in-depth)."""
    return f"session:{hashlib.sha256(token.encode()).hexdigest()}"


def _user_sessions_key(user_id: str) -> str:
    return f"user_sessions:{user_id}"


# ---------------------------------------------------------------------------
# CSRF — Signed Double-Submit Cookie (HMAC bound to session)
# ---------------------------------------------------------------------------

def generate_csrf_token(session_token: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode(),
        session_token.encode(),
        hashlib.sha256,
    ).hexdigest()


def verify_csrf_token(session_token: str, csrf_token: str) -> bool:
    expected = generate_csrf_token(session_token)
    return hmac.compare_digest(expected, csrf_token)


# ---------------------------------------------------------------------------
# Session CRUD (Redis)
# ---------------------------------------------------------------------------

async def create_session(
    user_id: str,
    request: Request,
    extra: dict | None = None,
) -> str:
    token = generate_session_token()
    now = datetime.now(UTC).isoformat()
    data = {
        "user_id": user_id,
        "created_at": now,
        "last_active": now,
        "rotated_at": now,
        "ip": request.client.host if request.client else "unknown",
        "user_agent": request.headers.get("user-agent", ""),
        **(extra or {}),
    }
    redis = get_redis()
    key = _session_key(token)
    pipe = redis.pipeline(transaction=True)
    pipe.set(key, json.dumps(data), ex=settings.SESSION_TTL)
    pipe.sadd(_user_sessions_key(user_id), key)
    pipe.expire(_user_sessions_key(user_id), settings.SESSION_TTL + 3600)
    await pipe.execute()
    return token


async def get_session(token: str) -> dict | None:
    redis = get_redis()
    raw = await redis.get(_session_key(token))
    if raw is None:
        return None
    return json.loads(raw)


async def delete_session(token: str) -> None:
    redis = get_redis()
    key = _session_key(token)
    raw = await redis.get(key)
    pipe = redis.pipeline()
    pipe.delete(key)
    if raw:
        user_id = json.loads(raw).get("user_id")
        if user_id:
            pipe.srem(_user_sessions_key(user_id), key)
    await pipe.execute()


# ---------------------------------------------------------------------------
# Expiration checks
# ---------------------------------------------------------------------------

def _parse_ts(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


def is_expired(session: dict) -> bool:
    now = datetime.now(UTC)
    created = _parse_ts(session["created_at"])
    last_active = _parse_ts(session["last_active"])

    if (now - created).total_seconds() > settings.SESSION_TTL:
        return True
    if (now - last_active).total_seconds() > settings.SESSION_IDLE_TTL:
        return True
    return False


def needs_rotation(session: dict) -> bool:
    elapsed = (datetime.now(UTC) - _parse_ts(session["rotated_at"])).total_seconds()
    return elapsed >= settings.TOKEN_ROTATION_INTERVAL


# ---------------------------------------------------------------------------
# Touch (update last_active + refresh TTL)
# ---------------------------------------------------------------------------

_touch_script_obj = None


def _get_touch_script():
    """Lazy-registered Lua script (cachea SHA1 localmente; redis-py usa
    EVALSHA internamente com fallback pra EVAL+NOSCRIPT)."""
    global _touch_script_obj
    if _touch_script_obj is None:
        _touch_script_obj = get_redis().register_script(_LUA_TOUCH)
    return _touch_script_obj


async def touch_session(token: str, session: dict) -> None:
    """Atualiza last_active e refresh TTL. NO-OP para sessions em grace.

    N-7: dois gates.
    - In-memory check: short-circuit se o caller já tem dict grace — evita
      roundtrip Redis e protege callers que bypassem o middleware.
    - Lua atomic (CAS): re-lê o estado em Redis e aborta se grace=true lá.
      Fecha o TOCTOU onde outra request concorrente rotacionou a sessão entre
      get_session e touch_session — dict in-memory seria stale e sem esse
      gate sobrescreveria o grace (TTL 60s) com TTL cheio."""
    if session.get("grace"):
        return

    now = datetime.now(UTC)
    session["last_active"] = now.isoformat()
    remaining = settings.SESSION_TTL - int(
        (now - _parse_ts(session["created_at"])).total_seconds()
    )
    ttl = max(remaining, 1)

    script = _get_touch_script()
    await script(
        keys=[_session_key(token)],
        args=[json.dumps(session), str(ttl)],
    )


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------

async def rotate_session(old_token: str, session: dict) -> str | None:
    """Rotaciona token. Retorna novo token, ou None se rotação concorrente
    (lock em posse de outro) ou sequencial (outro já rotacionou, o session
    do caller está stale) já aconteceu.

    Lock previne last-write-wins entre rotações simultâneas. CAS em
    rotated_at previne rotações sequenciais a partir de snapshot obsoleto:
    sem ele, 2 requests que leram a mesma sessão pré-rotação criariam 2
    sessões novas — uma fica órfã viva até SESSION_TTL."""
    old_key = _session_key(old_token)
    lock_key = f"rotate_lock:{old_key}"

    redis = get_redis()
    # SET NX — só quem adquirir o lock rotaciona; TTL 5s cobre execução normal
    acquired = await redis.set(lock_key, "1", nx=True, ex=5)
    if not acquired:
        return None

    try:
        # CAS: reler estado dentro do lock. Se outra rotação (já liberou o
        # lock) completou, old_key foi sobrescrito como grace OU o rotated_at
        # mudou. Em ambos os casos, o session recebido do caller é stale.
        raw = await redis.get(old_key)
        if raw is None:
            return None
        current = json.loads(raw)
        if current.get("grace") or current.get("rotated_at") != session.get("rotated_at"):
            return None

        # Fonte de verdade: estado fresco do Redis, não o dict mutado pelo caller.
        session = current

        new_token = generate_session_token()
        now = datetime.now(UTC)

        # New session keeps full data with updated timestamps
        session["last_active"] = now.isoformat()
        session["rotated_at"] = now.isoformat()
        session.pop("grace", None)

        new_key = _session_key(new_token)
        user_id = session["user_id"]

        remaining = settings.SESSION_TTL - int(
            (now - _parse_ts(session["created_at"])).total_seconds()
        )
        ttl = max(remaining, 1)

        # Old session is demoted to grace: read-only, non-renewable, short TTL
        grace_data = {**session, "grace": True}

        pipe = redis.pipeline(transaction=True)
        pipe.set(new_key, json.dumps(session), ex=ttl)
        pipe.set(old_key, json.dumps(grace_data), ex=settings.TOKEN_ROTATION_GRACE)
        pipe.srem(_user_sessions_key(user_id), old_key)
        pipe.sadd(_user_sessions_key(user_id), new_key)
        pipe.expire(_user_sessions_key(user_id), ttl + 3600)
        await pipe.execute()

        return new_token
    finally:
        await redis.delete(lock_key)


# ---------------------------------------------------------------------------
# Per-user invalidation (atomic via Lua script)
# ---------------------------------------------------------------------------

async def delete_all_user_sessions(user_id: str) -> int:
    redis = get_redis()
    set_key = _user_sessions_key(user_id)
    # redis.eval runs the Lua script atomically inside Redis
    result = await redis.eval(_LUA_DELETE_ALL, 1, set_key)  # noqa: S307
    return int(result)


async def list_user_sessions(user_id: str) -> list[dict]:
    redis = get_redis()
    set_key = _user_sessions_key(user_id)
    session_keys = await redis.smembers(set_key)
    if not session_keys:
        return []

    pipe = redis.pipeline()
    for sk in session_keys:
        pipe.get(sk)
    results = await pipe.execute()

    sessions = []
    stale: list[str] = []
    for sk, raw in zip(session_keys, results, strict=False):
        if raw:
            sessions.append(json.loads(raw))
        else:
            stale.append(sk)

    if stale:
        await redis.srem(set_key, *stale)

    return sessions


# ---------------------------------------------------------------------------
# Cookie helpers
# ---------------------------------------------------------------------------

def set_session_cookies(response: Response, session_token: str) -> None:
    # Session cookie: strict SameSite, HTTP-only
    response.set_cookie(
        key=settings.session_cookie,
        value=session_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        domain=settings.COOKIE_DOMAIN,
        path=settings.COOKIE_PATH,
        max_age=settings.SESSION_TTL,
    )
    # CSRF cookie: lax SameSite, readable by JS
    response.set_cookie(
        key=settings.csrf_cookie,
        value=generate_csrf_token(session_token),
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        domain=settings.COOKIE_DOMAIN,
        path=settings.COOKIE_PATH,
        max_age=settings.SESSION_TTL,
    )


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(
        key=settings.session_cookie,
        domain=settings.COOKIE_DOMAIN,
        path=settings.COOKIE_PATH,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        httponly=True,
    )
    response.delete_cookie(
        key=settings.csrf_cookie,
        domain=settings.COOKIE_DOMAIN,
        path=settings.COOKIE_PATH,
        secure=settings.COOKIE_SECURE,
        samesite="lax",
        httponly=False,
    )
