"""Modelos SQLAlchemy (tablas de la base de datos).

Hoy solo existe ``users``. Las tablas ``otp_codes`` y ``login_sessions``
(sección 3.1 del parcial) se agregan en sus propias ramas.
"""
from datetime import datetime, timezone

from sqlalchemy import DateTime, String
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
