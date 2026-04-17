"""Regression tests para M-3: Redis TLS com verify-full.
Restaura o `_redis` global após cada teste pra não contaminar a suite."""
from unittest.mock import AsyncMock, patch

import pytest

import app.core.redis as redis_mod
from app.core.config import settings
from app.core.redis import init_redis


@pytest.fixture(autouse=True)
def _restore_redis():
    saved = redis_mod._redis
    yield
    redis_mod._redis = saved


class TestRedisTLSConfig:
    async def test_no_tls_no_ssl_kwargs(self):
        with patch.object(settings, "REDIS_TLS", False):
            with patch("app.core.redis.aioredis.from_url",
                       return_value=AsyncMock()) as m:
                await init_redis()
                _, kwargs = m.call_args
                assert "ssl_cert_reqs" not in kwargs
                assert "ssl_ca_certs" not in kwargs

    async def test_tls_enforces_verify(self):
        with patch.object(settings, "REDIS_TLS", True):
            with patch.object(settings, "REDIS_CA_CERT", ""):
                with patch("app.core.redis.aioredis.from_url",
                           return_value=AsyncMock()) as m:
                    await init_redis()
                    _, kwargs = m.call_args
                    assert kwargs["ssl_cert_reqs"] == "required"
                    assert kwargs["ssl_check_hostname"] is True

    async def test_tls_with_ca_cert_uses_it(self):
        with patch.object(settings, "REDIS_TLS", True):
            with patch.object(settings, "REDIS_CA_CERT", "/path/to/ca.pem"):
                with patch("app.core.redis.aioredis.from_url",
                           return_value=AsyncMock()) as m:
                    await init_redis()
                    _, kwargs = m.call_args
                    assert kwargs["ssl_ca_certs"] == "/path/to/ca.pem"
