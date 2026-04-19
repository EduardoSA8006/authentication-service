"""Primitivo de rate limit sliding-window via Redis ZSET.

Fixed window (versão anterior) permite abuso na borda: 100 reqs nos últimos
2s da janela atual + 100 nos primeiros 2s da próxima = 200 em 4s.
Sliding window conta os últimos N segundos reais — imune ao abuse de borda.

N-10: toda a operação (prune + check + add + ttl + retry_after) em UM único
script Lua. Elimina o revert pós-pipeline que tinha race sob concorrência alta
e corta um round-trip.
"""
import secrets
import time

from app.core.redis import get_redis

# Script Lua atômico: prune → check → add-or-reject.
# Retorna {count, retry_after} mantendo contrato antigo (caller checa count > limit).
# Em over-limit, count é count_atual + 1 (não adicionamos, mas sinalizamos excesso).
_LUA_SLIDING_WINDOW = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local window = tonumber(ARGV[5])
local ttl = tonumber(ARGV[6])

redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
local count = redis.call('ZCARD', key)

if count >= limit then
    local earliest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 1
    if #earliest >= 2 then
        local oldest_score = tonumber(earliest[2])
        retry_after = math.max(math.floor(oldest_score + window - now) + 1, 1)
    end
    return {count + 1, retry_after}
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, ttl)
return {count + 1, 0}
"""


_sliding_window_script = None


def _get_sliding_window_script():
    """Lazy-registered Lua script (redis-py cachea SHA localmente + fallback
    automático pra EVAL em NOSCRIPT)."""
    global _sliding_window_script
    if _sliding_window_script is None:
        _sliding_window_script = get_redis().register_script(_LUA_SLIDING_WINDOW)
    return _sliding_window_script


async def sliding_window_incr(
    key: str, limit: int, window: int,
) -> tuple[int, int]:
    """Incrementa contador sliding-window e retorna (count, retry_after).

    Se count ≤ limit: retorna (count, 0). Request é aceita.
    Se count > limit: retorna (count, retry_after_seconds). Request deve ser rejeitada.

    Implementação: ZSET com timestamp como score. Script Lua atômico faz
    prune + check + add (ou reject) em uma única operação Redis.

    Raises Exception em erros de Redis (caller fail-closed com 503).
    """
    now = time.time()
    # Membro único garante que múltiplas reqs no mesmo microssegundo não colidem
    member = f"{now:.6f}:{secrets.token_hex(4)}"
    cutoff = now - window

    script = _get_sliding_window_script()
    result = await script(
        keys=[key],
        args=[now, cutoff, limit, member, window, window + 1],
    )
    return int(result[0]), int(result[1])
