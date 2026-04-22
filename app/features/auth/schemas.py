import uuid
from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, Field, computed_field, field_validator, model_validator

from app.features.auth.validators import (
    validate_and_format_name,
    validate_and_normalize_email,
    validate_date_of_birth,
    validate_password,
)


class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    date_of_birth: date

    @field_validator("name")
    @classmethod
    def check_name(cls, v: str) -> str:
        return validate_and_format_name(v)

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_and_normalize_email(v)

    @field_validator("date_of_birth")
    @classmethod
    def check_dob(cls, v: date) -> date:
        validate_date_of_birth(v)
        return v

    @model_validator(mode="after")
    def check_password_with_context(self) -> "RegisterRequest":
        validate_password(self.password, context=[self.name, self.email])
        return self


class LoginRequest(BaseModel):
    email: str
    # min_length=1: rejeita senha vazia no schema (422) antes de bater no
    # hasher — evita ciclo Argon2id (~300ms) para caso trivialmente inválido.
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return validate_and_normalize_email(v)


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        return validate_and_normalize_email(v)


class UserResponse(BaseModel):
    id: uuid.UUID
    name: str
    email: str
    date_of_birth: date
    is_verified: bool
    created_at: datetime
    # Lido do ORM via from_attributes; escondido da serialização. Frontend
    # consome apenas `password_advisory` (computed), que abstrai o timestamp
    # interno — evita expor quando exatamente a senha foi detectada em breach.
    password_breach_detected_at: datetime | None = Field(default=None, exclude=True)

    model_config = {"from_attributes": True}

    @computed_field  # type: ignore[prop-decorator]
    @property
    def password_advisory(self) -> Literal["breached"] | None:
        """N-5: `"breached"` se HIBP detectou a senha em vazamento (via worker
        pós-login). Frontend deve exibir banner com link pra trocar senha.
        Null = sem aviso pendente (nunca detectado ou senha já foi trocada).

        Nota (N-25): este campo vaza no /openapi.json quando DEBUG=True —
        atacante descobriria que existe tracking server-side de breach.
        Em produção, DEBUG=false (enforced pelo validate_settings) desabilita
        /docs/redoc/openapi.json; o schema não é exposto. Trade-off aceito."""
        return "breached" if self.password_breach_detected_at is not None else None


class DeleteAccountRequest(BaseModel):
    # min_length=1: rejeita senha vazia em 422 antes do Argon2 verify
    # (~300ms). Mesma defesa-em-profundidade do LoginRequest.
    password: str = Field(min_length=1, max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        # Validação estrita (mesmo padrão de RegisterRequest). Strings
        # malformadas rejeitadas com 422 antes de tocarem rate-limit Redis —
        # anti-enum continua intacto para emails *bem-formados* (existente vs
        # não-existente vs soft-deleted → todos 202 via worker silencioso).
        # 422 em formato inválido é um leak aceitável (mesma superfície do
        # /register) e o trade-off vale pra não poluir keyspace Redis com
        # payloads arbitrários do cliente.
        return validate_and_normalize_email(v)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(max_length=128)


class ResetPasswordRequest(BaseModel):
    # Validação de força + contextual é feita no service (precisa do user
    # pra context name/email). Aqui só length guard.
    # token_urlsafe(32) produz exatamente 43 chars base64url; min_length=32
    # é um lower bound defensivo (sobra para futuras mudanças sem quebrar
    # tokens vivos), max_length=128 continua protegendo contra abuse.
    token: str = Field(min_length=32, max_length=128)
    # min_length=8: rejeita senha curta em 422 ANTES do _consume_reset_token
    # (GETDEL one-shot). Sem isso, new_password="" consome o token e aborta
    # na validação de força — usuário precisa pedir /forgot-password de novo.
    # validate_password continua checando entropy, breach e context no
    # service; o mínimo aqui é só guard-rail contra o side-effect do consume.
    new_password: str = Field(min_length=8, max_length=128)


class MessageResponse(BaseModel):
    message: str


class SessionInfo(BaseModel):
    """Resumo público de uma sessão ativa. NÃO inclui o token nem campos que
    permitiriam hijack. IP é mostrado só em prefixo /24 (IPv4) ou /48 (IPv6)
    — identifica a rede sem expor endereço completo no payload da response
    (evita logging de IP cheio em access logs intermediários)."""

    session_id: str = Field(min_length=64, max_length=64)
    created_at: datetime
    last_active: datetime
    ip_prefix: str | None
    device: str  # Browser + OS via _ua_summary; nunca o UA bruto.
    is_current: bool


class SessionListResponse(BaseModel):
    sessions: list[SessionInfo]
