"""Modelos SQLAlchemy (tablas de la base de datos).

Existen ``users`` y ``otp_codes``. La tabla ``login_sessions``
(sección 3.1 del parcial) se agrega en su propia rama.
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


def _utcnow() -> datetime:
    """Devuelve la fecha y hora actual en UTC (valor por defecto de las columnas)."""
    return datetime.now(timezone.utc)


class User(Base):
    """Usuario registrado en el sistema.

    Attributes:
        id: identificador único autoincremental.
        email: correo del usuario; único y siempre en minúsculas.
        password_hash: contraseña hasheada con bcrypt (nunca en texto plano).
        full_name: nombre completo.
        created_at: fecha de creación (UTC).
        updated_at: fecha de la última modificación (UTC).
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class OtpCode(Base):
    """Código OTP de un solo uso enviado al correo del usuario.

    Attributes:
        id: identificador único autoincremental.
        user_id: usuario dueño del código (``users.id``).
        code: código de 6 dígitos.
        expires_at: momento en que el código deja de ser válido (15 min tras crearse).
        used: True si ya se usó o se invalidó; un código usado nunca vuelve a valer.
        created_at: fecha de creación (UTC).
    """

    __tablename__ = "otp_codes"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True, nullable=False)
    code: Mapped[str] = mapped_column(String(6), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
