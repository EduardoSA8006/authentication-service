"""Regression tests para M-4: sliding window elimina abuso de borda."""
import asyncio

import pytest

from app.core.rate_limit import sliding_window_incr


class TestSlidingWindow:
    async def test_allows_under_limit(self, _clean_redis):
        for i in range(5):
            count, retry = await sliding_window_incr("test:a", limit=10, window=60)
            assert count == i + 1
            assert retry == 0

    async def test_blocks_over_limit(self, _clean_redis):
        for _ in range(10):
            await sliding_window_incr("test:b", limit=10, window=60)
        count, retry = await sliding_window_incr("test:b", limit=10, window=60)
        assert count > 10
        assert retry > 0

    async def test_border_abuse_prevented(self, _clean_redis):
        """Regression: fixed window permite 2× limit em 4s na borda.
        Sliding window: qualquer sequência de N reqs em <window tem mesma contagem."""
        # 10 reqs "agora"
        for _ in range(10):
            await sliding_window_incr("test:border", limit=10, window=5)
        # Imediatamente mais uma → deve bloquear (fixed window deixaria passar
        # se estivesse na borda do bucket)
        count, retry = await sliding_window_incr("test:border", limit=10, window=5)
        assert count > 10
        assert retry > 0

    async def test_reverts_own_entry_when_over(self, _clean_redis):
        """Request que passa do limite não deve fuel o counter futuramente.
        Senão atacante em loop trava própria janela para sempre."""
        for _ in range(10):
            await sliding_window_incr("test:revert", limit=10, window=60)
        # 11º: retornou over → foi revertido
        count1, _ = await sliding_window_incr("test:revert", limit=10, window=60)
        # 12º: contagem igual (o 11º não contou)
        count2, _ = await sliding_window_incr("test:revert", limit=10, window=60)
        assert count1 == count2

    @pytest.mark.slow
    async def test_window_slides(self, _clean_redis):
        """Entradas antigas saem da janela conforme tempo passa."""
        for _ in range(5):
            await sliding_window_incr("test:slide", limit=10, window=1)
        await asyncio.sleep(1.2)  # janela inteira passou
        count, retry = await sliding_window_incr("test:slide", limit=10, window=1)
        assert count == 1
        assert retry == 0
