import uuid
from datetime import date, datetime

from pydantic import BaseModel, field_validator, model_validator

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
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class VerifyEmailRequest(BaseModel):
    token: str


class UserResponse(BaseModel):
    id: uuid.UUID
    name: str
    email: str
    date_of_birth: date
    is_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class DeleteAccountRequest(BaseModel):
    password: str


class MessageResponse(BaseModel):
    message: str
