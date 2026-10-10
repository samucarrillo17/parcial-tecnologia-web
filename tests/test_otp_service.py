"""Tests unitarios de app/services/otp_service.py."""
import re

from sqlalchemy import select

from app.models import OtpCode, User
from app.security import hash_password
from app.services.otp_service import generate_otp, invalidate_user_codes


def make_user(db_session) -> User:
    """Crea y guarda un usuario de prueba directamente en la BD."""
    user = User(email="ana@gmail.com", password_hash=hash_password("Segura123"), full_name="Ana")
    db_session.add(user)
    db_session.commit()
    return user


def test_generate_otp_returns_six_digits(db_session):
    """El código generado tiene exactamente 6 dígitos numéricos."""
    code = generate_otp(db_session, make_user(db_session))

    assert re.fullmatch(r"\d{6}", code)


def test_generate_otp_is_stored_unused_with_15_minutes_expiry(db_session):
    """El código se guarda sin usar y con vigencia de 15 minutos."""
    user = make_user(db_session)
    code = generate_otp(db_session, user)

    row = db_session.scalar(select(OtpCode).where(OtpCode.user_id == user.id))
    assert row.code == code
    assert row.used is False
    minutes = (row.expires_at - row.created_at).total_seconds() / 60
    assert 14.9 <= minutes <= 15.1


def test_new_otp_invalidates_previous_ones(db_session):
    """Al generar un código nuevo, los anteriores quedan marcados como usados."""
    user = make_user(db_session)
    generate_otp(db_session, user)
    second = generate_otp(db_session, user)

    rows = db_session.scalars(select(OtpCode).order_by(OtpCode.id)).all()
    assert [r.used for r in rows] == [True, False]
    assert rows[1].code == second


def test_invalidate_user_codes_marks_all_as_used(db_session):
    """invalidate_user_codes deja al usuario sin ningún código vigente."""
    user = make_user(db_session)
    generate_otp(db_session, user)

    invalidate_user_codes(db_session, user.id)

    unused = db_session.scalars(select(OtpCode).where(OtpCode.used.is_(False))).all()
    assert unused == []
