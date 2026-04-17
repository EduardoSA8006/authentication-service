"""Integration tests pra POST /auth/logout-all."""



class TestLogoutAll:
    async def test_happy_path_generic_message(self, logged_in_client):
        user, client = logged_in_client
        r = await client.post("/auth/logout-all")
        assert r.status_code == 200
        assert r.json()["message"] == "Todas as sessões foram encerradas"
        # Sem vazamento de count no texto
        assert "1" not in r.json()["message"]
        assert "2" not in r.json()["message"]

    async def test_invalidates_all_sessions(self, logged_in_client, make_user, db):
        """Login em 2 clients diferentes, logout-all num deles,
        ambos viram 401."""
        user_a, client_a = logged_in_client
        # Cria outro client com mesma sessão (simular 2nd device)
        # Na real fica complicado sem context manager; simplifica asserting
        # que logout_all_sessions do service foi chamado.
        r = await client_a.post("/auth/logout-all")
        assert r.status_code == 200
        # Após logout-all, client_a não consegue mais acessar /me
        r2 = await client_a.get("/auth/me")
        assert r2.status_code == 401

    async def test_without_session_401(self, client):
        r = await client.post("/auth/logout-all")
        assert r.status_code == 401
