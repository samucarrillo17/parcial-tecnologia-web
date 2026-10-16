"""Tests unitarios de verify_otp (app/services/otp_service.py)."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.models import OtpCode, User
from app.security import hash_password
from app.services.otp_service import generate_otp, verify_otp


def make_user(db_session) -> User:
    """Crea y guarda un usuario de prueba directamente en la BD."""
    user = User(email="ana@gmail.com", password_hash=hash_password("Segura123"), full_name="Ana")
    db_session.add(user)
    db_session.commit()
    return user


def test_verify_otp_correct_code_returns_true_and_consumes_it(db_session):
    """Un código correcto es válido y queda marcado como usado."""
    user = make_user(db_session)
    code = generate_otp(db_session, user)

    assert verify_otp(db_session, user, code) is True

    row = db_session.scalar(select(OtpCode).where(OtpCode.user_id == user.id))
    assert row.used is True


def test_verify_otp_cannot_be_used_twice(db_session):
    """El mismo código no sirve una segunda vez."""
    user = make_user(db_session)
    code = generate_otp(db_session, user)

    assert verify_otp(db_session, user, code) is True
    assert verify_otp(db_session, user, code) is False


def test_verify_otp_wrong_code_returns_false_and_keeps_code_valid(db_session):
    """Un código incorrecto falla y no gasta el código real."""
    user = make_user(db_session)
    code = generate_otp(db_session, user)
    wrong = "000000" if code != "000000" else "111111"

    assert verify_otp(db_session, user, wrong) is False
    assert verify_otp(db_session, user, code) is True


def test_verify_otp_expired_code_returns_false(db_session):
    """Un código pasado de su fecha de expiración no es válido."""
    user = make_user(db_session)
    code = generate_otp(db_session, user)
    row = db_session.scalar(select(OtpCode).where(OtpCode.user_id == user.id))
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    assert verify_otp(db_session, user, code) is False


def test_verify_otp_only_latest_code_is_valid(db_session):
    """Si se genera un código nuevo, el anterior deja de servir."""
    user = make_user(db_session)
    first = generate_otp(db_session, user)
    second = generate_otp(db_session, user)

    if first != second:  # (con 6 dígitos al azar podrían coincidir)
        assert verify_otp(db_session, user, first) is False
    assert verify_otp(db_session, user, second) is True


def test_verify_otp_user_without_codes_returns_false(db_session):
    """Un usuario que nunca hizo login no tiene código que verificar."""
    user = make_user(db_session)

    assert verify_otp(db_session, user, "123456") is False