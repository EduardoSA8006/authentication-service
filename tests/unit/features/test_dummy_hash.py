"""N-14: dummy hash regenera quando params do Argon2 mudam (evita timing drift
entre 'user existe' e 'user não existe')."""
import app.features.auth.service as service_mod


class TestDummyHashParamsDrift:
    def setup_method(self):
        """Reseta cache entre testes."""
        service_mod._DUMMY_HASH = None

    def test_first_call_generates(self):
        h = service_mod._get_dummy_hash()
        assert h.startswith("$argon2")
        assert service_mod._DUMMY_HASH == h

    def test_subsequent_calls_reuse_cache(self):
        h1 = service_mod._get_dummy_hash()
        h2 = service_mod._get_dummy_hash()
        # Mesmo objeto (string idêntica) — não regenerou
        assert h1 == h2

    def test_regenerates_when_params_upgraded(self):
        """Simula bump de memory_cost: check_needs_rehash retorna True no
        dummy antigo → _get_dummy_hash regenera com params novos."""
        from argon2 import PasswordHasher

        original_ph = service_mod._ph
        try:
            # Gera dummy com params atuais
            h_old = service_mod._get_dummy_hash()

            # Troca _ph por um com params mais pesados — simula upgrade
            service_mod._ph = PasswordHasher(
                time_cost=4,       # subiu de 3
                memory_cost=131072,  # subiu de 65536
                parallelism=4,
                hash_len=32,
                salt_len=16,
            )

            h_new = service_mod._get_dummy_hash()
            assert h_new != h_old
            # Novo hash usa os params novos
            assert "m=131072" in h_new
            assert "t=4" in h_new
        finally:
            service_mod._ph = original_ph
            service_mod._DUMMY_HASH = None
