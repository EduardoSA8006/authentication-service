import asyncio
import quopri
import re
import time

import httpx


class MailHog:
    """Wrapper sobre a API HTTP do MailHog."""

    BASE = "http://127.0.0.1:8025"

    async def get_messages(self) -> list[dict]:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{self.BASE}/api/v2/messages")
            r.raise_for_status()
            return r.json().get("items", [])

    async def clear(self) -> None:
        async with httpx.AsyncClient() as c:
            await c.delete(f"{self.BASE}/api/v1/messages")

    async def wait_for(self, count: int = 1, timeout: float = 2.0) -> list[dict]:
        """Polling — resolve race do asyncio.create_task pendente."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            msgs = await self.get_messages()
            if len(msgs) >= count:
                return msgs
            await asyncio.sleep(0.05)
        msgs = await self.get_messages()
        raise TimeoutError(
            f"Expected {count} messages in {timeout}s, got {len(msgs)}"
        )

    async def last(self) -> dict:
        msgs = await self.wait_for(count=1)
        return msgs[-1]

    async def extract_verification_token(self) -> str:
        """Extrai o token do link de verificação do último email.
        Decodifica quoted-printable (MailHog armazena raw body com =3D etc)."""
        msg = await self.last()
        body = msg["Content"]["Body"]
        decoded = quopri.decodestring(body).decode("utf-8", errors="replace")
        m = re.search(r"token=([A-Za-z0-9_-]+)", decoded)
        if not m:
            raise ValueError("No verification token in email body")
        return m.group(1)
