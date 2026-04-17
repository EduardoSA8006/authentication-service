import hashlib
import hmac
import json
import secrets
from datetime import UTC, datetime

from fastapi import Request, Response

from app.core.config import settings
from app.core.redis import get_redis

_TOKEN_BYTES = 36  # 36 bytes → exactly 48 chars in base64url

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
    pipe = redis.pipeline()
    pipe.set(key, json.dumps(data), ex=settings.SESSION_TTL)
    pipe.sadd(_user_sessions_key(user_id), key)
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

async def touch_session(token: str, session: dict) -> None:
    now = datetime.now(UTC)
    session["last_active"] = now.isoformat()
    remaining = settings.SESSION_TTL - int(
        (now - _parse_ts(session["created_at"])).total_seconds()
    )
    ttl = max(remaining, 1)
    redis = get_redis()
    await redis.set(_session_key(token), json.dumps(session), ex=ttl)


# ---------------------------------------------------------------------------
# Rotation
# ---------------------------------------------------------------------------

async def rotate_session(old_token: str, session: dict) -> str | None:
    """Rotaciona token. Retorna novo token, ou None se rotação concorrente
    já está em andamento (outra request venceu o lock).

    Lock previne last-write-wins: sem ele, 2 requests simultâneas que passam
    de TOKEN_ROTATION_INTERVAL criam 2 sessões novas, uma fica órfã viva até TTL."""
    old_key = _session_key(old_token)
    lock_key = f"rotate_lock:{old_key}"

    redis = get_redis()
    # SET NX — só quem adquirir o lock rotaciona; TTL 5s cobre execução normal
    acquired = await redis.set(lock_key, "1", nx=True, ex=5)
    if not acquired:
        return None

    try:
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

        pipe = redis.pipeline()
        pipe.set(new_key, json.dumps(session), ex=ttl)
        pipe.set(old_key, json.dumps(grace_data), ex=settings.TOKEN_ROTATION_GRACE)
        pipe.srem(_user_sessions_key(user_id), old_key)
        pipe.sadd(_user_sessions_key(user_id), new_key)
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
