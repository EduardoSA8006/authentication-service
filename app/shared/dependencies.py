from fastapi import Request

from app.core.exceptions import UnauthorizedError


async def get_current_session(request: Request) -> dict:
    session = getattr(request.state, "session", None)
    if session is None:
        raise UnauthorizedError
    return session
