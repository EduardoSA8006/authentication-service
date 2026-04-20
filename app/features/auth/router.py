from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.middleware import get_client_ip
from app.core.security import clear_session_cookies, set_session_cookies
from app.shared.dependencies import get_current_session
from app.features.auth import rate_limit as rl
from app.core.rate_limit import check_rate_limit
from app.features.auth.schemas import (
    ChangePasswordRequest,
    DeleteAccountRequest,
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RegisterRequest,
    ResendVerificationRequest,
    ResetPasswordRequest,
    UserResponse,
    VerifyEmailRequest,
)
from app.features.auth.service import (
    change_password_request,
    forgot_password,
    get_user_from_session,
    login_user,
    logout_all_sessions,
    logout_user,
    register_user,
    resend_verification_email,
    reset_password,
    soft_delete_user,
    verify_email,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=MessageResponse, status_code=202)
async def register(
    body: RegisterRequest,
    request: Request,
):
    """202 Accepted — register-queue pattern. Handler não toca DB/HIBP/SMTP;
    todo trabalho pesado vai para worker assíncrono. Resposta idêntica e em
    µs para qualquer caminho (email novo, duplicado, ou senha breached),
    fechando o side-channel de timing."""
    ip = get_client_ip(request)
    await check_rate_limit("register:ip", ip, *rl.REGISTER_IP)
    await check_rate_limit("register:email", body.email, *rl.REGISTER_EMAIL)

    await register_user(
        name=body.name,
        email=body.email,
        password=body.password,
        date_of_birth=body.date_of_birth,
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
    ip = get_client_ip(request)
    await check_rate_limit("login:ip", ip, *rl.LOGIN_IP)

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
    ip = get_client_ip(request)
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
    ip = get_client_ip(request)
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
    ip = get_client_ip(request)
    await check_rate_limit("verify:ip", ip, *rl.VERIFY_IP)

    await verify_email(body.token, db)
    return MessageResponse(message="Email verificado com sucesso")


@router.post("/resend-verification", response_model=MessageResponse)
async def resend_verification(
    body: ResendVerificationRequest,
    request: Request,
):
    ip = get_client_ip(request)
    await check_rate_limit("resend:ip", ip, *rl.RESEND_IP)
    await check_rate_limit("resend:email", body.email, *rl.RESEND_EMAIL)
    await resend_verification_email(body.email)
    return MessageResponse(
        message="Se este email estiver disponível, você receberá um email de confirmação",
    )


@router.get("/me", response_model=UserResponse)
async def me(
    request: Request,
    session: dict = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    ip = get_client_ip(request)
    await check_rate_limit("me:ip", ip, *rl.ME_IP)

    user = await get_user_from_session(session, db)
    return UserResponse.model_validate(user)


@router.post("/forgot-password", response_model=MessageResponse, status_code=202)
async def forgot_password_endpoint(
    body: ForgotPasswordRequest,
    request: Request,
):
    """Anti-enum: sempre 202. Worker assíncrono lida com email existente ou não."""
    ip = get_client_ip(request)
    await check_rate_limit("forgot_password:ip", ip, *rl.FORGOT_PASSWORD_IP)
    await check_rate_limit("forgot_password:email", body.email, *rl.FORGOT_PASSWORD_EMAIL)

    await forgot_password(body.email)

    return MessageResponse(
        message="Se este email estiver cadastrado, você receberá instruções para redefinir a senha",
    )


@router.post("/change-password", response_model=MessageResponse, status_code=202)
async def change_password_endpoint(
    body: ChangePasswordRequest,
    request: Request,
    session: dict = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """Autenticada + CSRF + proof-of-possession da senha atual.
    Emite email com link — troca só concretiza em /reset-password."""
    ip = get_client_ip(request)
    user_id = session["user_id"]
    await check_rate_limit("change_password:ip", ip, *rl.CHANGE_PASSWORD_IP)
    await check_rate_limit("change_password:user", user_id, *rl.CHANGE_PASSWORD_USER)

    await change_password_request(user_id, body.current_password, db)

    return MessageResponse(
        message="Email de confirmação enviado para alterar sua senha",
    )


@router.post("/reset-password", response_model=MessageResponse)
async def reset_password_endpoint(
    body: ResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Sincrono: valida token + nova senha, persiste hash, invalida sessões.
    Retorna 400 se token inválido/expirado, senha fraca, ou senha em breach."""
    ip = get_client_ip(request)
    await check_rate_limit("reset_password:ip", ip, *rl.RESET_PASSWORD_IP)

    await reset_password(body.token, body.new_password, db, ip)

    return MessageResponse(message="Senha redefinida com sucesso")


@router.post("/delete-account", response_model=MessageResponse)
async def delete_account(
    body: DeleteAccountRequest,
    request: Request,
    response: Response,
    session: dict = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    ip = get_client_ip(request)
    await check_rate_limit("delete:ip", ip, *rl.DELETE_ACCOUNT_IP)
    await check_rate_limit("delete:user", session["user_id"], *rl.DELETE_ACCOUNT_USER)

    await soft_delete_user(session["user_id"], body.password, db)
    clear_session_cookies(response)
    return MessageResponse(
        message="Conta marcada para exclusão. Será removida permanentemente em 7 dias.",
    )
