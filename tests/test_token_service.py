"""Tests unitarios de app/services/token_service.py."""
import jwt
from sqlalchemy import select

from app.middleware import JWT_ALGORITHM, JWT_SECRET
from app.models import LoginSession, User
from app.security import hash_password
from app.services.token_service import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_access_token,
    create_session_token,
)


def decode(token: str) -> dict:
    """Decodifica un token con la misma clave que usa el middleware."""
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


def test_create_access_token_has_required_claims():
    """El token trae sub (id como texto), iat, exp posterior a iat y jti."""
    token, expires_in = create_access_token(7)

    payload = decode(token)
    assert payload["sub"] == "7"
    assert payload["exp"] > payload["iat"]
    assert payload["jti"]
    assert expires_in == ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert payload["exp"] - payload["iat"] == expires_in


def test_create_access_token_tokens_are_unique():
    """Dos tokens del mismo usuario son distintos (aunque se emitan en el mismo segundo)."""
    first, _ = create_access_token(1)
    second, _ = create_access_token(1)

    assert first != second
    assert decode(first)["jti"] != decode(second)["jti"]


def test_create_session_token_registers_active_session(db_session):
    """El token emitido queda registrado en login_sessions, que es lo que exige el middleware."""
    user = User(email="ana@gmail.com", password_hash=hash_password("Segura123"), full_name="Ana")
    db_session.add(user)
    db_session.commit()

    token, expires_in = create_session_token(db_session, user.id)

    session = db_session.scalar(select(LoginSession))
    assert session.token == token
    assert session.user_id == user.id
    assert expires_in == ACCESS_TOKEN_EXPIRE_MINUTES * 60
