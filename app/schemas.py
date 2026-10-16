"""Esquemas Pydantic: validación de lo que entra y sale de la API.

Pydantic revisa automáticamente los datos de cada petición. Si algo no
cumple las reglas, FastAPI responde 422 sin que el endpoint llegue a ejecutarse.
"""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class RegisterRequest(BaseModel):
    """Datos necesarios para registrar un usuario.

    Reglas:
        - ``email``: formato de correo válido (se guarda en minúsculas).
        - ``password``: 8 a 72 caracteres, con mayúscula, minúscula y número.
        - ``full_name``: no vacío, máximo 100 caracteres.
    """

    email: EmailStr = Field(..., examples=["ana.perez@gmail.com"])
    password: str = Field(..., min_length=8, max_length=72, examples=["Segura123"])
    full_name: str = Field(..., min_length=1, max_length=100, examples=["Ana Pérez"])

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "ana.perez@gmail.com",
                "password": "Segura123",
                "full_name": "Ana Pérez",
            }
        }
    )

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """Pasa el email a minúsculas para que ANA@x.com y ana@x.com sean el mismo."""
        return value.lower()

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        """Exige mayúscula, minúscula y número, y un máximo de 72 bytes.

        bcrypt solo procesa los primeros 72 bytes de la contraseña, por eso
        se rechaza una contraseña más larga en lugar de truncarla en silencio.
        """
        if not any(c.isupper() for c in value):
            raise ValueError("La contraseña debe tener al menos una mayúscula")
        if not any(c.islower() for c in value):
            raise ValueError("La contraseña debe tener al menos una minúscula")
        if not any(c.isdigit() for c in value):
            raise ValueError("La contraseña debe tener al menos un número")
        if len(value.encode("utf-8")) > 72:
            raise ValueError("La contraseña es demasiado larga (máximo 72 bytes)")
        return value

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, value: str) -> str:
        """Quita espacios sobrantes y rechaza nombres vacíos (solo espacios)."""
        value = value.strip()
        if not value:
            raise ValueError("El nombre completo no puede estar vacío")
        return value


class UserResponse(BaseModel):
    """Datos públicos de un usuario. Nunca incluye la contraseña ni su hash."""

    id: int
    email: EmailStr
    full_name: str
    created_at: datetime

    # from_attributes permite construir este esquema directamente desde un objeto User de SQLAlchemy.
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "email": "ana.perez@gmail.com",
                "full_name": "Ana Pérez",
                "created_at": "2026-10-09T16:55:00Z",
            }
        },
    )


class LoginRequest(BaseModel):
    """Credenciales para iniciar sesión.

    Aquí NO se exigen las reglas de fortaleza del registro: en el login solo
    se comprueba que la contraseña coincida, y así no se revela la política.
    """

    email: EmailStr = Field(..., examples=["ana.perez@gmail.com"])
    password: str = Field(..., min_length=1, max_length=72, examples=["Segura123"])

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"email": "ana.perez@gmail.com", "password": "Segura123"}
        }
    )

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """Pasa el email a minúsculas, igual que en el registro."""
        return value.lower()


class LoginResponse(BaseModel):
    """Respuesta del login: confirma el envío del OTP (nunca incluye el código)."""

    message: str
    expires_in_minutes: int

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Te enviamos un código de verificación a tu correo",
                "expires_in_minutes": 15,
            }
        }
    )

class UserUpdate(BaseModel):
    """Datos permitidos para actualizar el perfil del usuario."""

    full_name: str | None = Field(None, min_length=1, max_length=100, examples=["Ana María Pérez"])
    email: EmailStr | None = Field(None, examples=["ana.nuevo@gmail.com"])

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "full_name": "Ana María Pérez",
                "email": "ana.nuevo@gmail.com",
            }
        }
    )

    

class ResendOtpRequest(BaseModel):
    """Correo del usuario que pide que se le reenvíe el código OTP."""

    email: EmailStr = Field(..., examples=["ana.perez@gmail.com"])

    model_config = ConfigDict(json_schema_extra={"example": {"email": "ana.perez@gmail.com"}})

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """Pasa el email a minúsculas, igual que en el registro y el login."""
        return value.lower()


class ResendOtpResponse(BaseModel):
    """Respuesta de reenvío de OTP.

    El mensaje es el mismo exista o no el correo, para no revelar qué
    correos están registrados.
    """

    message: str
    expires_in_minutes: int

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Si el correo está registrado, te enviamos un código de verificación",
                "expires_in_minutes": 15,
            }
        }
    )



class LogoutResponse(BaseModel):
    """Confirmación de cierre de sesión."""

    message: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "message": "Sesión cerrada correctamente"
            }
        }
    )
