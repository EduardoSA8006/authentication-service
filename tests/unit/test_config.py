"""Unit tests para validate_settings_for_production."""
from unittest.mock import patch

from app.core.config import settings, validate_settings_for_production


class TestProductionValidator:
    def test_debug_true_warns(self):
        with patch.object(settings, "DEBUG", True):
            warnings = validate_settings_for_production()
            assert any("DEBUG is True" in w for w in warnings)

    def test_insecure_secret_key_warns(self):
        with patch.object(
            settings, "SECRET_KEY",
            "change-me-in-production-use-a-random-64-char-string",
        ):
            warnings = validate_settings_for_production()
            assert any("placeholder" in w for w in warnings)

    def test_short_secret_warns(self):
        with patch.object(settings, "SECRET_KEY", "short"):
            warnings = validate_settings_for_production()
            assert any("SECRET_KEY is too short" in w for w in warnings)

    def test_weak_postgres_password_warns(self):
        with patch.object(settings, "POSTGRES_PASSWORD", "auth"):
            warnings = validate_settings_for_production()
            assert any("POSTGRES_PASSWORD" in w for w in warnings)

    def test_empty_redis_password_warns(self):
        with patch.object(settings, "REDIS_PASSWORD", ""):
            warnings = validate_settings_for_production()
            assert any("REDIS_PASSWORD is empty" in w for w in warnings)

    def test_weak_redis_password_warns(self):
        with patch.object(settings, "REDIS_PASSWORD", "redis"):
            warnings = validate_settings_for_production()
            assert any("REDIS_PASSWORD" in w and "default" in w for w in warnings)

    def test_weak_minio_warns(self):
        with patch.object(settings, "MINIO_ACCESS_KEY", "minioadmin"):
            warnings = validate_settings_for_production()
            assert any("MINIO_ACCESS_KEY" in w for w in warnings)

    def test_cookie_insecure_warns(self):
        with patch.object(settings, "COOKIE_SECURE", False):
            warnings = validate_settings_for_production()
            assert any("COOKIE_SECURE is False" in w for w in warnings)

    def test_localhost_allowed_hosts_warns(self):
        with patch.object(settings, "ALLOWED_HOSTS", ["localhost", "127.0.0.1"]):
            warnings = validate_settings_for_production()
            assert any("localhost" in w for w in warnings)

    def test_wildcard_hosts_warns(self):
        with patch.object(settings, "ALLOWED_HOSTS", ["*"]):
            warnings = validate_settings_for_production()
            assert any("wildcard" in w for w in warnings)

    def test_frontend_http_warns(self):
        with patch.object(settings, "FRONTEND_URL", "http://example.com"):
            warnings = validate_settings_for_production()
            assert any("FRONTEND_URL uses http" in w for w in warnings)

    def test_frontend_localhost_warns(self):
        with patch.object(settings, "FRONTEND_URL", "http://localhost:3000"):
            warnings = validate_settings_for_production()
            assert any("FRONTEND_URL contains 'localhost'" in w for w in warnings)

    def test_smtp_mailhog_warns(self):
        with patch.object(settings, "SMTP_HOST", "mailhog"):
            warnings = validate_settings_for_production()
            assert any("SMTP_HOST is 'mailhog'" in w for w in warnings)

    def test_smtp_tls_off_warns(self):
        """Ambos TLS flags off → email em plaintext, warning emitido."""
        with patch.object(settings, "SMTP_TLS", False), \
                patch.object(settings, "SMTP_IMPLICIT_TLS", False):
            warnings = validate_settings_for_production()
            assert any(
                "both False" in w and "plaintext" in w for w in warnings
            )

    def test_smtp_both_tls_flags_warns(self):
        """STARTTLS + SMTPS implícito ao mesmo tempo é config inválida."""
        with patch.object(settings, "SMTP_TLS", True), \
                patch.object(settings, "SMTP_IMPLICIT_TLS", True):
            warnings = validate_settings_for_production()
            assert any("both True" in w for w in warnings)

    def test_smtp_implicit_tls_only_no_warn(self):
        """SMTPS implícito (465) só — config válida, sem warning."""
        with patch.object(settings, "SMTP_TLS", False), \
                patch.object(settings, "SMTP_IMPLICIT_TLS", True):
            warnings = validate_settings_for_production()
            assert not any("plaintext" in w for w in warnings)
            assert not any("both True" in w for w in warnings)

    def test_empty_allowed_hosts_warns(self):
        """ALLOWED_HOSTS=[] é fail-closed, mas misconfig — warning pra detectar
        antes de staging ficar 'sem responder nada'."""
        with patch.object(settings, "ALLOWED_HOSTS", []):
            warnings = validate_settings_for_production()
            assert any("ALLOWED_HOSTS is empty" in w for w in warnings)

    def test_no_postgres_ssl_warns(self):
        with patch.object(settings, "POSTGRES_SSL", False):
            warnings = validate_settings_for_production()
            assert any("POSTGRES_SSL is False" in w for w in warnings)

    def test_no_redis_tls_warns(self):
        with patch.object(settings, "REDIS_TLS", False):
            warnings = validate_settings_for_production()
            assert any("REDIS_TLS is False" in w for w in warnings)

    def test_database_url_sync_uses_verify_full_without_custom_ca(self):
        """SSL sem CA custom deve usar verify-full (system CA bundle), não
        verify-ca — senão hostname não é validado e MitM é possível com
        qualquer cert emitido por uma CA do bundle."""
        with patch.object(settings, "POSTGRES_SSL", True), \
                patch.object(settings, "POSTGRES_CA_CERT", ""):
            url = settings.database_url_sync
            assert "sslmode=verify-full" in url
            assert "sslmode=verify-ca" not in url

    def test_database_url_sync_uses_verify_full_with_custom_ca(self):
        """CA custom pinning: verify-full + sslrootcert."""
        with patch.object(settings, "POSTGRES_SSL", True), \
                patch.object(settings, "POSTGRES_CA_CERT", "/etc/ssl/ca.pem"):
            url = settings.database_url_sync
            assert "sslmode=verify-full" in url
            assert "sslrootcert=/etc/ssl/ca.pem" in url
