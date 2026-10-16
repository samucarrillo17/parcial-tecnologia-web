"""Servicio de generación de códigos OTP (PyOTP).

Un OTP (One-Time Password) es un código de 6 dígitos, de un solo uso y con
vida corta. Este módulo lo genera, lo guarda en la tabla ``otp_codes`` y
invalida los códigos anteriores del mismo usuario.
"""
import hmac
import os
from datetime import datetime, timedelta, timezone

import pyotp
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import OtpCode, User

OTP_DIGITS = 6
# El parcial exige un máximo de 15 minutos: el valor del .env nunca puede superarlo.
OTP_EXPIRE_MINUTES = min(int(os.getenv("OTP_EXPIRE_MINUTES", "15")), 15)


def _invalidate_unused(db: Session, user_id: int) -> None:
    """Marca como usados todos los códigos vigentes del usuario (sin hacer commit)."""
    db.execute(
        update(OtpCode)
        .where(OtpCode.user_id == user_id, OtpCode.used.is_(False))
        .values(used=True)
    )


def invalidate_user_codes(db: Session, user_id: int) -> None:
    """Invalida los códigos OTP vigentes de un usuario y guarda el cambio.

    Se usa, por ejemplo, cuando el correo no pudo enviarse: el código que
    nadie recibió no debe quedar activo.

    Args:
        db: sesión de base de datos.
        user_id: id del usuario cuyos códigos se invalidan.
    """
    _invalidate_unused(db, user_id)
    db.commit()


def generate_otp(db: Session, user: User) -> str:
    """Genera un OTP de 6 dígitos válido 15 minutos y lo guarda en la BD.

    Primero invalida los códigos anteriores del usuario, de modo que solo el
    último enviado funcione. El código sale de ``pyotp.TOTP`` con un secreto
    aleatorio nuevo en cada llamada, lo que produce 6 dígitos impredecibles.

    Args:
        db: sesión de base de datos.
        user: usuario que recibirá el código.

    Returns:
        str: el código de 6 dígitos (se envía por correo, nunca se devuelve en la API).
    """
    _invalidate_unused(db, user.id)

    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret, digits=OTP_DIGITS, interval=OTP_EXPIRE_MINUTES * 60).now()

    db.add(
        OtpCode(
            user_id=user.id,
            code=code,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES),
            used=False,
        )
    )
    db.commit()
    return code

def verify_otp(db: Session, user: User, code: str) -> bool:
    """Comprueba el OTP de un usuario y, si es correcto, lo consume.

    Un código es válido solo si es el último generado para el usuario, no se
    ha usado y no ha expirado. Si es válido se marca como usado, así que no
    sirve una segunda vez.

    Por seguridad devuelve solo True/False: el llamador no distingue entre
    "no existe", "expiró" o "es incorrecto".

    Args:
        db: sesión de base de datos.
        user: usuario que intenta verificar.
        code: código de 6 dígitos que escribió el usuario.

    Returns:
        bool: True si el código era válido (y quedó consumido); False si no.
    """
    otp = db.scalar(
        select(OtpCode)
        .where(OtpCode.user_id == user.id, OtpCode.used.is_(False))
        .order_by(OtpCode.id.desc())
        .limit(1)
    )
    if otp is None:
        return False

    # SQLite guarda las fechas sin zona horaria: se vuelve a marcar como UTC
    # para poder compararla con la hora actual (que sí la tiene).
    expires_at = otp.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        return False

    # compare_digest compara en tiempo constante (evita ataques por tiempo).
    if not hmac.compare_digest(otp.code, code):
        return False

    # UPDATE atómico: solo "gana" una petición aunque lleguen dos a la vez con
    # el mismo código. La segunda encuentra used=True y no actualiza ninguna fila.
    result = db.execute(
        update(OtpCode).where(OtpCode.id == otp.id, OtpCode.used.is_(False)).values(used=True)
    )
    db.commit()
    return result.rowcount == 1