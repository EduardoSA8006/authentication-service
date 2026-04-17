from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.middleware import _get_client_ip
from app.core.security import clear_session_cookies, set_session_cookies
from app.shared.dependencies import get_current_session
from app.features.auth import rate_limit as rl
from app.features.auth.rate_limit import check_rate_limit
from app.features.auth.schemas import (
    DeleteAccountRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    ResendVerificationRequest,
    UserResponse,
    VerifyEmailRequest,
)
from app.features.auth.service import (
    get_user_from_session,
    login_user,
    logout_all_sessions,
    logout_user,
    register_user,
    resend_verification_email,
    soft_delete_user,
    verify_email,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=MessageResponse)
async def register(
    body: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    await check_rate_limit("register:ip", ip, *rl.REGISTER_IP)
    await check_rate_limit("register:email", body.email, *rl.REGISTER_EMAIL)

    await register_user(
        name=body.name,
        email=body.email,
        password=body.password,
        date_of_birth=body.date_of_birth,
        db=db,
        request=request,
    )

    return MessageResponse(
        message="Se este email estiver disponível, você receberá um email de confirmação",
    )


@router.post("/login", response_model=UserResponse)
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    await check_rate_limit("login:ip", ip, *rl.LOGIN_IP)
    await check_rate_limit("login:email", body.email, *rl.LOGIN_EMAIL)

    user, session_token = await login_user(
        email=body.email,
        password=body.password,
        db=db,
        request=request,
    )

    set_session_cookies(response, session_token)
    return UserResponse.model_validate(user)


@router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    response: Response,
    session: dict = Depends(get_current_session),
):
    ip = _get_client_ip(request)
    await check_rate_limit("logout:ip", ip, *rl.LOGOUT_IP)

    token = getattr(request.state, "session_token", None)
    if token:
        await logout_user(token)
    clear_session_cookies(response)
    return MessageResponse(message="Logout realizado")


@router.post("/logout-all", response_model=MessageResponse)
async def logout_all(
    request: Request,
    response: Response,
    session: dict = Depends(get_current_session),
):
    ip = _get_client_ip(request)
    await check_rate_limit("logout:ip", ip, *rl.LOGOUT_IP)

    await logout_all_sessions(session["user_id"])
    clear_session_cookies(response)
    return MessageResponse(message="Todas as sessões foram encerradas")


@router.post("/verify-email", response_model=MessageResponse)
async def verify_email_endpoint(
    body: VerifyEmailRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    await check_rate_limit("verify:ip", ip, *rl.VERIFY_IP)

    await verify_email(body.token, db)
    return MessageResponse(message="Email verificado com sucesso")


@router.post("/resend-verification", response_model=MessageResponse)
async def resend_verification(
    body: ResendVerificationRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    await check_rate_limit("resend:ip", ip, *rl.RESEND_IP)
    await check_rate_limit("resend:email", body.email, *rl.RESEND_EMAIL)
    await resend_verification_email(body.email, db, request)
    return MessageResponse(
        message="Se este email estiver disponível, você receberá um email de confirmação",
    )


@router.get("/me", response_model=UserResponse)
async def me(
    request: Request,
    session: dict = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    await check_rate_limit("me:ip", ip, *rl.ME_IP)

    user = await get_user_from_session(session, db)
    return UserResponse.model_validate(user)


@router.post("/delete-account", response_model=MessageResponse)
async def delete_account(
    body: DeleteAccountRequest,
    request: Request,
    response: Response,
    session: dict = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    ip = _get_client_ip(request)
    await check_rate_limit("delete:ip", ip, *rl.DELETE_ACCOUNT_IP)

    await soft_delete_user(session["user_id"], body.password, db)
    clear_session_cookies(response)
    return MessageResponse(
        message="Conta marcada para exclusão. Será removida permanentemente em 7 dias.",
    )
