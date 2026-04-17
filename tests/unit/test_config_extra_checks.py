"""Regression tests para L-10: checks adicionais no validate_settings_for_production."""
from unittest.mock import patch

from app.core.config import settings, validate_settings_for_production


class TestExtraProductionChecks:
    def test_empty_trusted_proxy_ips_warns(self):
        with patch.object(settings, "TRUSTED_PROXY_IPS", []):
            warnings = validate_settings_for_production()
            assert any("TRUSTED_PROXY_IPS is empty" in w for w in warnings)

    def test_cookie_domain_not_suffix_of_frontend_warns(self):
        with patch.object(settings, "COOKIE_DOMAIN", ".other.com"):
            with patch.object(settings, "FRONTEND_URL", "https://app.example.com"):
                warnings = validate_settings_for_production()
                assert any("não é sufixo" in w for w in warnings)

    def test_cookie_domain_is_suffix_no_warning(self):
        with patch.object(settings, "COOKIE_DOMAIN", ".example.com"):
            with patch.object(settings, "FRONTEND_URL", "https://app.example.com"):
                warnings = validate_settings_for_production()
                assert not any("não é sufixo" in w for w in warnings)

    def test_session_ttl_over_30_days_warns(self):
        with patch.object(settings, "SESSION_TTL", 60 * 86400):  # 60 days
            warnings = validate_settings_for_production()
            assert any("SESSION_TTL" in w and ">30" in w for w in warnings)

    def test_session_ttl_normal_no_warning(self):
        with patch.object(settings, "SESSION_TTL", 604800):  # 7 dias
            warnings = validate_settings_for_production()
            assert not any("SESSION_TTL" in w and ">30" in w for w in warnings)

    def test_idle_ttl_exceeds_absolute_warns(self):
        with patch.object(settings, "SESSION_IDLE_TTL", 999999):
            with patch.object(settings, "SESSION_TTL", 604800):
                warnings = validate_settings_for_production()
                assert any("SESSION_IDLE_TTL > SESSION_TTL" in w for w in warnings)
