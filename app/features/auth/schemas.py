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
    password: str = Field(max_length=128)

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
        Null = sem aviso pendente (nunca detectado ou senha já foi trocada)."""
        return "breached" if self.password_breach_detected_at is not None else None


class DeleteAccountRequest(BaseModel):
    password: str = Field(max_length=128)


class ForgotPasswordRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def check_email(cls, v: str) -> str:
        # Fallback strip/lower se normalização falhar — anti-enum exige que
        # emails inválidos cheguem no worker e sejam silenciados lá, não
        # rejeitados aqui com 422 (que distinguiria do caminho 202).
        try:
            return validate_and_normalize_email(v)
        except ValueError:
            return v.strip().lower()


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(max_length=128)


class ResetPasswordRequest(BaseModel):
    # Validação de força + contextual é feita no service (precisa do user
    # pra context name/email). Aqui só length guard.
    token: str = Field(min_length=1, max_length=128)
    new_password: str = Field(max_length=128)


class MessageResponse(BaseModel):
    message: str
