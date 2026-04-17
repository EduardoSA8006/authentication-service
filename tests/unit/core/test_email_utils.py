"""Unit tests para helpers de email e SMTP injection guard."""
import pytest

from app.core.email import _hash_email, send_email


class TestHashEmail:
    def test_deterministic(self):
        assert _hash_email("a@b.com") == _hash_email("a@b.com")

    def test_different_inputs_different(self):
        assert _hash_email("a@b.com") != _hash_email("c@d.com")

    def test_length(self):
        assert len(_hash_email("test@example.com")) == 16

    def test_hex_chars(self):
        h = _hash_email("test@example.com")
        assert all(c in "0123456789abcdef" for c in h)

    def test_case_sensitive(self):
        # Hash HMAC é determinístico; emails diferentes = hashes diferentes
        assert _hash_email("A@B.com") != _hash_email("a@b.com")


class TestSMTPInjectionGuard:
    async def test_rejects_crlf_in_to(self):
        with pytest.raises(ValueError, match="to"):
            await send_email(
                "user@example.com\r\nBcc: evil@x",
                "subject",
                "verification",
                {"name": "n", "link": "l"},
            )

    async def test_rejects_lf_in_to(self):
        with pytest.raises(ValueError, match="to"):
            await send_email(
                "user@example.com\nBcc: evil@x",
                "subject",
                "verification",
                {"name": "n", "link": "l"},
            )

    async def test_rejects_null_in_to(self):
        with pytest.raises(ValueError, match="to"):
            await send_email(
                "user@example.com\x00evil",
                "subject",
                "verification",
                {"name": "n", "link": "l"},
            )

    async def test_rejects_crlf_in_subject(self):
        with pytest.raises(ValueError, match="subject"):
            await send_email(
                "user@example.com",
                "sub\r\nX-Injected: yes",
                "verification",
                {"name": "n", "link": "l"},
            )


class TestTemplateRendering:
    async def test_html_escapes_xss(self):
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        from pathlib import Path
        import app.core.email as email_mod
        template_dir = Path(email_mod.__file__).parent / "templates" / "emails"
        env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html"]),
        )
        html = env.get_template("verification.html").render(
            name="<script>alert(1)</script>",
            link="https://example.com/x",
        )
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    async def test_txt_contains_link(self):
        from jinja2 import Environment, FileSystemLoader
        from pathlib import Path
        import app.core.email as email_mod
        template_dir = Path(email_mod.__file__).parent / "templates" / "emails"
        env = Environment(loader=FileSystemLoader(template_dir))
        txt = env.get_template("verification.txt").render(
            name="João",
            link="https://example.com/verify?token=ABC",
        )
        assert "João" in txt
        assert "https://example.com/verify?token=ABC" in txt
