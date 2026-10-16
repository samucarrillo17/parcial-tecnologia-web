"""Tests de POST /auth/resend-otp.

Se simula solo el envío del correo (``send_otp``); BD, servicio OTP y
endpoint son los reales.
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models import OtpCode, User
from app.routes import auth as auth_routes
from app.security import hash_password
from app.services.email_service import EmailDeliveryError

EMAIL = "ana@gmail.com"


@pytest.fixture()
def sent(monkeypatch):
    """Reemplaza el envío de correo y guarda lo que se habría enviado."""
    outbox: list[tuple[str, str]] = []
    monkeypatch.setattr(auth_routes, "send_otp", lambda email, code: outbox.append((email, code)))
    return outbox


@pytest.fixture()
def user(db_session) -> User:
    """Usuario registrado de prueba."""
    u = User(email=EMAIL, password_hash=hash_password("Segura123"), full_name="Ana")
    db_session.add(u)
    db_session.commit()
    return u


def test_resend_sends_new_otp_and_invalidates_previous(client, db_session, user, sent, monkeypatch):
    """Reenviar crea un código nuevo vigente y deja usado el anterior."""
    monkeypatch.setattr(auth_routes, "RESEND_COOLDOWN_SECONDS", 0)
    client.post("/auth/resend-otp", json={"email": EMAIL})
    response = client.post("/auth/resend-otp", json={"email": EMAIL})

    assert response.status_code == 200
    assert response.json()["expires_in_minutes"] == 15
    rows = db_session.scalars(select(OtpCode).order_by(OtpCode.id)).all()
    assert [r.used for r in rows] == [True, False]
    assert len(sent) == 2
    assert sent[-1] == (EMAIL, rows[-1].code)


def test_resend_response_never_contains_the_code(client, user, sent):
    """El código solo va por correo, nunca en la respuesta de la API."""
    response = client.post("/auth/resend-otp", json={"email": EMAIL})

    assert sent[0][1] not in response.text


def test_resend_unknown_email_returns_same_response_and_sends_nothing(client, db_session, user, sent):
    """Correo no registrado: misma respuesta 200, sin correo y sin OTP."""
    known = client.post("/auth/resend-otp", json={"email": EMAIL})
    unknown = client.post("/auth/resend-otp", json={"email": "nadie@gmail.com"})

    assert unknown.status_code == 200
    assert unknown.json() == known.json()
    assert len(sent) == 1  # solo el del usuario real
    assert len(db_session.scalars(select(OtpCode)).all()) == 1


def test_resend_within_cooldown_does_not_send_again(client, db_session, user, sent):
    """Dos reenvíos seguidos: el segundo no envía otro correo (cooldown)."""
    client.post("/auth/resend-otp", json={"email": EMAIL})
    response = client.post("/auth/resend-otp", json={"email": EMAIL})

    assert response.status_code == 200
    assert len(sent) == 1
    assert len(db_session.scalars(select(OtpCode)).all()) == 1


def test_resend_after_cooldown_sends_again(client, db_session, user, sent):
    """Pasada la espera, el reenvío vuelve a funcionar."""
    client.post("/auth/resend-otp", json={"email": EMAIL})
    old = db_session.scalar(select(OtpCode))
    old.created_at = datetime.now(timezone.utc) - timedelta(minutes=2)
    db_session.commit()

    client.post("/auth/resend-otp", json={"email": EMAIL})

    assert len(sent) == 2


def test_resend_invalid_email_returns_422(client):
    """Un correo mal formado responde 422."""
    assert client.post("/auth/resend-otp", json={"email": "no-es-correo"}).status_code == 422


def test_resend_smtp_failure_returns_503_and_leaves_no_active_otp(client, db_session, user, monkeypatch):
    """Si el correo no sale: 503 y ningún código queda activo."""

    def boom(email, code):
        raise EmailDeliveryError("fallo simulado")

    monkeypatch.setattr(auth_routes, "send_otp", boom)

    response = client.post("/auth/resend-otp", json={"email": EMAIL})

    assert response.status_code == 503
    assert db_session.scalars(select(OtpCode).where(OtpCode.used.is_(False))).all() == []