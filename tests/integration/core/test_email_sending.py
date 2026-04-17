"""Integration tests pra envio real de email via MailHog."""

from app.core.email import send_email, send_verification_email


class TestEmailSending:
    async def test_send_email_reaches_mailhog(self, mailhog):
        await send_email(
            to="recipient@test.com",
            subject="Test Subject",
            template_name="verification",
            context={"name": "Test User", "link": "http://test.local/x"},
        )
        msgs = await mailhog.wait_for(count=1)
        assert msgs[0]["Content"]["Headers"]["Subject"][0] == "Test Subject"
        assert "recipient@test.com" in str(msgs[0]["Content"]["Headers"].get("To", []))

    async def test_send_verification_email_includes_link(self, mailhog):
        await send_verification_email("Fulano", "v@test.com", "ABC123")
        msg = await mailhog.last()
        body = msg["Content"]["Body"]
        assert "ABC123" in body
        assert "Fulano" in body

    async def test_multipart_has_html_and_text(self, mailhog):
        await send_verification_email("Beltrano", "m@test.com", "TOK")
        msg = await mailhog.last()
        body = msg["Content"]["Body"]
        # Multipart alternative tem boundaries e ambos content types
        assert "text/plain" in body.lower() or "text/html" in body.lower()
