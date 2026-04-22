"""N-10: background tasks — observability + graceful drain."""
import asyncio

from app.features.auth.service import (
    _background_tasks,
    _spawn,
    drain_background_tasks,
)


async def _noop():
    await asyncio.sleep(0)


async def _slow(duration: float):
    await asyncio.sleep(duration)


async def _boom():
    raise RuntimeError("intentional")


class TestSpawn:
    async def test_label_in_task_name(self):
        task = _spawn(_noop(), label="test_label:42")
        assert task.get_name() == "test_label:42"
        await task
        # Discard via done callback — task sai do set
        assert task not in _background_tasks

    async def test_logs_failure(self, caplog):
        """Worker que falhou é logado com label — essencial pra incident response."""
        import logging
        caplog.set_level(logging.ERROR, logger="app.features.auth.service")

        _spawn(_boom(), label="boom_test")
        await asyncio.sleep(0.05)

        assert any(
            "Background task failed: boom_test" in r.message for r in caplog.records
        )

    async def test_logs_schedule(self, caplog):
        import logging
        caplog.set_level(logging.INFO, logger="app.features.auth.service")

        task = _spawn(_noop(), label="sched_test")
        await task

        assert any(
            "Background task scheduled: sched_test" in r.message
            for r in caplog.records
        )


class TestDrain:
    async def test_drain_empty_returns_zero(self):
        dropped = await drain_background_tasks(timeout=1.0)
        assert dropped == 0

    async def test_drain_completes_fast_tasks(self):
        _spawn(_noop(), label="drain_fast_1")
        _spawn(_noop(), label="drain_fast_2")

        dropped = await drain_background_tasks(timeout=1.0)
        assert dropped == 0

    async def test_drain_reports_pending_after_timeout(self, caplog):
        """Task lento não drena → conta no retorno + loga o label."""
        import logging
        caplog.set_level(logging.ERROR, logger="app.features.auth.service")

        task = _spawn(_slow(2.0), label="slow_drain_test")

        try:
            dropped = await drain_background_tasks(timeout=0.1)
            assert dropped == 1
            assert any(
                "slow_drain_test" in r.message and "did not drain" in r.message
                for r in caplog.records
            )
        finally:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, RuntimeError):
                pass
