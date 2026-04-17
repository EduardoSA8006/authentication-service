"""Primitivo de rate limit sliding-window via Redis ZSET.

Fixed window (versão anterior) permite abuso na borda: 100 reqs nos últimos
2s da janela atual + 100 nos primeiros 2s da próxima = 200 em 4s.
Sliding window conta os últimos N segundos reais — imune ao abuse de borda.
"""
import secrets
import time

from app.core.redis import get_redis


async def sliding_window_incr(
    key: str, limit: int, window: int,
) -> tuple[int, int]:
    """Incrementa contador sliding-window e retorna (count, retry_after).

    Se count ≤ limit: retorna (count, 0). Request é aceita.
    Se count > limit: retorna (count, retry_after_seconds). Request deve ser rejeitada.

    Implementação: ZSET com timestamp como score. Cada request adiciona um
    membro único. `zremrangebyscore` remove entradas fora da janela antes de contar.

    Raises Exception em erros de Redis (caller fail-closed com 503).
    """
    redis = get_redis()
    now = time.time()
    # Membro único garante que múltiplas reqs no mesmo microssegundo não colidem
    member = f"{now:.6f}:{secrets.token_hex(4)}"
    cutoff = now - window

    pipe = redis.pipeline()
    pipe.zremrangebyscore(key, 0, cutoff)          # remove antigos
    pipe.zadd(key, {member: now})                   # registra atual
    pipe.zcard(key)                                 # conta total na janela
    pipe.expire(key, window + 1)                    # TTL maior que a janela
    _, _, count, _ = await pipe.execute()

    if count > limit:
        # Reverte o próprio add pra não "alimentar" o counter e bloquear indefinidamente
        await redis.zrem(key, member)
        # retry_after = quando o membro mais antigo da janela sair
        earliest = await redis.zrange(key, 0, 0, withscores=True)
        if earliest:
            retry_after = max(int(earliest[0][1] + window - now) + 1, 1)
        else:
            retry_after = 1
        return count, retry_after

    return count, 0
