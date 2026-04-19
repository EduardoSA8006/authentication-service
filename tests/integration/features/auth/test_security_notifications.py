"""Integration tests: notificações por email de eventos sensíveis.

Eventos cobertos:
- Novo dispositivo no login (via fingerprint de UA estável).
- Senha alterada (via /auth/reset-password).
- Conta marcada para exclusão (via /auth/delete-account).
- Todas as sessões encerradas (via /auth/logout-all).
"""
import quopri

from app.core.redis import get_redis
from app.features.auth.service import (
    _create_reset_token,
    _known_fingerprints_key,
)


_EMAIL = "notif@test.com"
_PASSWORD = "SenhaForte@2026"


def _decode_body(msg: dict) -> str:
    """Decode quoted-printable body para string utf-8 legível."""
    return quopri.decodestring(msg["Content"]["Body"]).decode("utf-8", errors="replace")


def _has_body_containing(msgs: list[dict], needles: list[str]) -> bool:
    """Algum msg no batch tem todos os `needles` no corpo decodificado?"""
    for m in msgs:
        body = _decode_body(m).lower()
        if all(n.lower() in body for n in needles):
            return True
    return False


def _count_with_needles(msgs: list[dict], needles: list[str]) -> int:
    return sum(
        1 for m in msgs
        if all(n.lower() in _decode_body(m).lower() for n in needles)
    )


class TestNewDeviceLoginNotification:
    async def test_first_login_ever_is_silent(
        self, client, make_user, mailhog, wait_for_workers,
    ):
        """Primeira fingerprint do usuário é silenciosa — evita ruído pós-registro."""
        await make_user(email=_EMAIL, password=_PASSWORD)

        r = await client.post("/auth/login", json={
            "email": _EMAIL, "password": _PASSWORD,
        })
        assert r.status_code == 200
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        assert _count_with_needles(msgs, ["Novo dispositivo"]) == 0

    async def test_new_fingerprint_sends_notification(
        self, client, make_user, mailhog, wait_for_workers,
    ):
        """Com fingerprint preexistente (simula login em device anterior),
        novo device dispara notificação."""
        user = await make_user(email=_EMAIL, password=_PASSWORD)
        # Preset uma fingerprint anterior — login atual será "novo device"
        redis = get_redis()
        await redis.sadd(_known_fingerprints_key(str(user.id)), "previous-device-fp")

        r = await client.post("/auth/login", json={
            "email": _EMAIL, "password": _PASSWORD,
        })
        assert r.status_code == 200
        await wait_for_workers()

        msgs = await mailhog.wait_for(count=1)
        assert _count_with_needles(msgs, ["Novo dispositivo"]) == 1

    async def test_same_device_second_login_no_notification(
        self, client, make_user, mailhog, wait_for_workers,
    ):
        """Login repetido do mesmo device (mesma fingerprint) → nenhum email novo."""
        user = await make_user(email=_EMAIL, password=_PASSWORD)
        redis = get_redis()
        await redis.sadd(_known_fingerprints_key(str(user.id)), "previous-device-fp")

        # Login 1: dispara notificação (fingerprint é nova)
        await client.post("/auth/login", json={"email": _EMAIL, "password": _PASSWORD})
        await wait_for_workers()

        # Login 2: mesma UA → mesma fingerprint → sem email
        await client.post("/auth/login", json={"email": _EMAIL, "password": _PASSWORD})
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        assert _count_with_needles(msgs, ["Novo dispositivo"]) == 1


class TestPasswordChangedNotification:
    async def test_reset_sends_password_changed_email(
        self, client, make_user, mailhog, wait_for_workers,
    ):
        user = await make_user(email=_EMAIL, password=_PASSWORD)
        token = await _create_reset_token(str(user.id))

        r = await client.post("/auth/reset-password", json={
            "token": token, "new_password": "NovaSenhaForte@2027",
        })
        assert r.status_code == 200
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        # Corpo contém "senha desta conta foi alterada"
        assert _has_body_containing(msgs, ["senha", "alterada"])

    async def test_failed_reset_does_not_notify(
        self, client, make_user, mailhog, wait_for_workers,
    ):
        """Reset com token inválido → 400, nenhum email de senha alterada."""
        await make_user(email=_EMAIL, password=_PASSWORD)

        r = await client.post("/auth/reset-password", json={
            "token": "bad-token", "new_password": "NovaSenhaForte@2027",
        })
        assert r.status_code == 400
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        assert _count_with_needles(msgs, ["senha", "alterada"]) == 0


class TestAccountDeletionNotification:
    async def test_soft_delete_sends_deletion_email(
        self, logged_in_client, mailhog, wait_for_workers,
    ):
        user, client = logged_in_client

        r = await client.post("/auth/delete-account", json={
            "password": "SenhaForte@2026",
        })
        assert r.status_code == 200
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        # "Conta agendada para exclusão" — "agendada" e "exclus" são ASCII
        assert _has_body_containing(msgs, ["agendada", "exclus"])

    async def test_delete_does_not_duplicate_sessions_terminated(
        self, logged_in_client, mailhog, wait_for_workers,
    ):
        """Dedup: delete_account chama delete_all_user_sessions direto (não
        logout_all_sessions) para evitar email de sessions_terminated em dupla
        com o email de deletion."""
        user, client = logged_in_client

        r = await client.post("/auth/delete-account", json={
            "password": "SenhaForte@2026",
        })
        assert r.status_code == 200
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        # Needle específica do sessions_terminated (presente só nesse template).
        # O email de deletion menciona "todas as suas sessões foram encerradas"
        # mas NÃO tem "ativas em sua conta".
        assert _count_with_needles(msgs, ["ativas em sua conta"]) == 0

    async def test_wrong_password_delete_does_not_notify(
        self, logged_in_client, mailhog, wait_for_workers,
    ):
        user, client = logged_in_client
        r = await client.post("/auth/delete-account", json={
            "password": "senhaErrada@2026",
        })
        assert r.status_code == 401
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        assert _count_with_needles(msgs, ["agendada", "exclus"]) == 0


class TestSessionsTerminatedNotification:
    async def test_logout_all_sends_notification(
        self, logged_in_client, mailhog, wait_for_workers,
    ):
        user, client = logged_in_client

        r = await client.post("/auth/logout-all")
        assert r.status_code == 200
        await wait_for_workers()

        msgs = await mailhog.get_messages()
        # Needle específica desse template (evita colisão com deletion email)
        assert _has_body_containing(msgs, ["ativas em sua conta"])


class TestFireAndForgetResilience:
    async def test_smtp_down_does_not_break_logout_all(
        self, logged_in_client, wait_for_workers,
    ):
        """Falhas de SMTP em workers de notificação não propagam ao cliente."""
        from unittest.mock import patch

        user, client = logged_in_client

        with patch(
            "app.features.auth.service.send_sessions_terminated_notification",
            side_effect=Exception("smtp down"),
        ):
            r = await client.post("/auth/logout-all")
            assert r.status_code == 200
            await wait_for_workers()

    async def test_smtp_down_does_not_break_login(
        self, client, make_user, wait_for_workers,
    ):
        """New-device notification worker silencia falhas de SMTP."""
        from unittest.mock import patch

        user = await make_user(email=_EMAIL, password=_PASSWORD)
        redis = get_redis()
        await redis.sadd(_known_fingerprints_key(str(user.id)), "previous-device-fp")

        with patch(
            "app.features.auth.service.send_new_login_notification",
            side_effect=Exception("smtp down"),
        ):
            r = await client.post("/auth/login", json={
                "email": _EMAIL, "password": _PASSWORD,
            })
            assert r.status_code == 200
            await wait_for_workers()


class TestUASummary:
    """_ua_summary é heurística — testa casos comuns + fallback."""
    def test_chrome_on_macos(self):
        from app.core.email import _ua_summary
        ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        assert _ua_summary(ua) == "Chrome em macOS"

    def test_firefox_on_windows(self):
        from app.core.email import _ua_summary
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
        assert _ua_summary(ua) == "Firefox em Windows"

    def test_safari_on_ios(self):
        from app.core.email import _ua_summary
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
        assert _ua_summary(ua) == "Safari em iOS"

    def test_edge_before_chrome(self):
        """Edge UA contém 'Chrome' — ordem importa no if/elif."""
        from app.core.email import _ua_summary
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
        assert _ua_summary(ua) == "Edge em Windows"

    def test_empty_ua(self):
        from app.core.email import _ua_summary
        assert _ua_summary("") == "dispositivo desconhecido"

    def test_unknown_ua_fallback(self):
        from app.core.email import _ua_summary
        result = _ua_summary("UnknownBot/1.0")
        assert "desconhecido" in result
