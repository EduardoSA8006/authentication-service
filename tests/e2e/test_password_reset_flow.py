"""E2E: esqueci senha → email → reset → login com nova senha.

Também cobre: troca autenticada (change-password) → email → reset."""


_EMAIL = "e2e-reset@test.com"
_OLD_PASSWORD = "SenhaVelha@2026"
_NEW_PASSWORD = "SenhaNova@2027"


class TestForgotPasswordFlow:
    async def test_full_forgot_flow(
        self, client, make_user, mailhog, wait_for_workers,
    ):
        # 1. Setup: user existe
        await make_user(email=_EMAIL, password=_OLD_PASSWORD)

        # 2. Solicita reset
        r = await client.post("/auth/forgot-password", json={"email": _EMAIL})
        assert r.status_code == 202
        await wait_for_workers()

        # 3. Extrai token do email
        token = await mailhog.extract_verification_token()
        assert len(token) > 20

        # 4. Aplica reset
        r = await client.post("/auth/reset-password", json={
            "token": token, "new_password": _NEW_PASSWORD,
        })
        assert r.status_code == 200

        # 5. Login com senha antiga falha (antes do sucesso pra não ter session ativa)
        r = await client.post("/auth/login", json={
            "email": _EMAIL, "password": _OLD_PASSWORD,
        })
        assert r.status_code == 401

        # 6. Login com nova senha funciona
        r = await client.post("/auth/login", json={
            "email": _EMAIL, "password": _NEW_PASSWORD,
        })
        assert r.status_code == 200


class TestChangePasswordFlow:
    async def test_full_change_flow(
        self, logged_in_client, mailhog, wait_for_workers,
    ):
        user, client = logged_in_client

        # 1. Usuário autenticado pede troca (com senha atual)
        r = await client.post("/auth/change-password", json={
            "current_password": "SenhaForte@2026",
        })
        assert r.status_code == 202
        await wait_for_workers()

        # 2. Extrai token
        token = await mailhog.extract_verification_token()

        # 3. Usa token em /reset-password (fora do contexto autenticado seria
        # o fluxo real; aqui o logged_in_client tem CSRF e passa também).
        r = await client.post("/auth/reset-password", json={
            "token": token, "new_password": _NEW_PASSWORD,
        })
        assert r.status_code == 200

        # 4. Sessão antiga foi invalidada — /me retorna 401 mesmo com cookie
        r = await client.get("/auth/me")
        assert r.status_code == 401

        # 5. Login com nova senha funciona
        r = await client.post("/auth/login", json={
            "email": user.email, "password": _NEW_PASSWORD,
        })
        assert r.status_code == 200
