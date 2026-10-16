"""Tests unitarios de POST /auth/login.

El envío del correo se simula (mock): aquí solo se prueba la lógica del endpoint.
"""
import re

import pytest
from sqlalchemy import select

from app.models import OtpCode, User
from app.rate_limit import limiter
from app.security import hash_password
from app.services.email_service import EmailDeliveryError

CREDENTIALS = {"email": "joshua.nieto@gmail.com", "password": "Segura123"}


@pytest.fixture()
def user(db_session) -> User:
    """Usuario registrado, creado directamente en la BD (sin pasar por /register)."""
    user = User(
        email=CREDENTIALS["email"],
        password_hash=hash_password(CREDENTIALS["password"]),
        full_name="Ana Pérez",
    )
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture()
def sent_emails(monkeypatch):
    """Reemplaza send_otp por una función que solo anota (email, código)."""
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr("app.routes.auth.send_otp", lambda email, code: calls.append((email, code)))
    return calls


def test_login_success_sends_otp(client, user, sent_emails):
    """Credenciales correctas: 200, se envía un OTP de 6 dígitos y no se filtra en la respuesta."""
    response = client.post("/auth/login", json=CREDENTIALS)

    assert response.status_code == 200
    assert response.json()["expires_in_minutes"] == 15
    assert len(sent_emails) == 1
    email, code = sent_emails[0]
    assert email == CREDENTIALS["email"]
    assert re.fullmatch(r"\d{6}", code)
    assert code not in response.text  # el código solo viaja por correo


def test_login_wrong_password_returns_401_without_sending_email(client, user, sent_emails):
    """Contraseña incorrecta: 401 y no se envía ningún correo."""
    response = client.post("/auth/login", json={**CREDENTIALS, "password": "Incorrecta1"})

    assert response.status_code == 401
    assert sent_emails == []


def test_login_unknown_email_returns_same_401(client, user, sent_emails):
    """Email inexistente: mismo 401 y mismo mensaje que con contraseña mala (no revela cuentas)."""
    wrong_password = client.post("/auth/login", json={**CREDENTIALS, "password": "Incorrecta1"})
    unknown_email = client.post("/auth/login", json={**CREDENTIALS, "email": "nadie@gmail.com"})

    assert unknown_email.status_code == 401
    assert unknown_email.json() == wrong_password.json()
    assert sent_emails == []


def test_login_email_is_case_insensitive(client, user, sent_emails):
    """El email se normaliza a minúsculas, igual que en el registro."""
    response = client.post("/auth/login", json={**CREDENTIALS, "email": "ANA.PEREZ@GMAIL.COM"})

    assert response.status_code == 200
    assert len(sent_emails) == 1


@pytest.mark.parametrize(
    "body",
    [
        {"email": "no-es-un-email", "password": "Segura123"},  # email mal formado
        {"email": CREDENTIALS["email"]},  # falta la contraseña
        {"email": CREDENTIALS["email"], "password": ""},  # contraseña vacía
    ],
)
def test_login_invalid_input_returns_422(client, body):
    """Datos mal formados se rechazan con 422 antes de tocar la BD."""
    response = client.post("/auth/login", json=body)

    assert response.status_code == 422


def test_login_email_failure_returns_503_and_invalidates_otp(client, db_session, user, monkeypatch):
    """Si el correo no se puede enviar: 503 y el código no queda activo."""

    def failing_send(email: str, code: str) -> None:
        raise EmailDeliveryError("SMTP caído")

    monkeypatch.setattr("app.routes.auth.send_otp", failing_send)

    response = client.post("/auth/login", json=CREDENTIALS)

    assert response.status_code == 503
    unused = db_session.scalars(select(OtpCode).where(OtpCode.used.is_(False))).all()
    assert unused == []


def test_login_rate_limit_returns_429(client, user, sent_emails):
    """Tras 5 intentos en un minuto, el sexto recibe 429."""
    limiter.enabled = True  # el fixture lo apaga; aquí sí lo necesitamos
    limiter.reset()

    statuses = [
        client.post("/auth/login", json={**CREDENTIALS, "password": "Incorrecta1"}).status_code
        for _ in range(6)
    ]

    assert statuses[:5] == [401] * 5
    assert statuses[5] == 429
