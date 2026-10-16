"""Tests de INTEGRACIÓN del login.

Aquí nada del flujo se simula salvo la frontera con el mundo exterior: el
servidor SMTP. Se recorre registro real -> login real -> otp_service real ->
email_service real -> BD real, y se comprueba el correo que "saldría".
"""
import re
import smtplib

import pytest
from sqlalchemy import select

from app.models import OtpCode, User

USER = {"email": "ana.perez@gmail.com", "password": "Segura123", "full_name": "Ana Pérez"}
CREDENTIALS = {"email": USER["email"], "password": USER["password"]}


@pytest.fixture()
def fake_smtp(monkeypatch):
    """Servidor SMTP falso: registra lo que recibiría en vez de enviarlo."""
    monkeypatch.setenv("EMAIL_BACKEND", "smtp")
    monkeypatch.setenv("SMTP_HOST", "smtp.prueba.local")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USER", "remitente@prueba.local")
    monkeypatch.setenv("SMTP_PASSWORD", "clave-de-prueba")

    class FakeSMTP:
        instances: list["FakeSMTP"] = []
        fail_on_send = False

        def __init__(self, host, port, timeout=None):
            self.host, self.port = host, port
            self.started_tls = False
            self.credentials = None
            self.messages = []
            FakeSMTP.instances.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def starttls(self):
            self.started_tls = True

        def login(self, user, password):
            self.credentials = (user, password)

        def send_message(self, message):
            if FakeSMTP.fail_on_send:
                raise smtplib.SMTPException("fallo simulado")
            self.messages.append(message)

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    return FakeSMTP


def code_in_email(message) -> str:
    """Extrae el código de 6 dígitos del cuerpo del correo."""
    match = re.search(r"\b(\d{6})\b", message.get_content())
    assert match, "el correo no contiene un código de 6 dígitos"
    return match.group(1)


def test_login_flow_sends_real_email_and_stores_matching_otp(client, db_session, fake_smtp):
    """Registro -> login: llega un correo con el OTP y ese mismo OTP queda en la BD."""
    assert client.post("/auth/register", json=USER).status_code == 201

    response = client.post("/auth/login", json=CREDENTIALS)

    assert response.status_code == 200
    # 1) El SMTP recibió exactamente un correo, bien dirigido y con conexión segura.
    assert len(fake_smtp.instances) == 1
    smtp = fake_smtp.instances[0]
    assert smtp.started_tls is True
    assert smtp.credentials == ("remitente@prueba.local", "clave-de-prueba")
    assert len(smtp.messages) == 1
    message = smtp.messages[0]
    assert message["To"] == USER["email"]
    # 2) El código del correo es el que quedó guardado, vigente y sin usar.
    user = db_session.scalar(select(User).where(User.email == USER["email"]))
    row = db_session.scalar(select(OtpCode).where(OtpCode.user_id == user.id))
    assert row.code == code_in_email(message)
    assert row.used is False
    minutes = (row.expires_at - row.created_at).total_seconds() / 60
    assert 14.9 <= minutes <= 15.1


def test_second_login_invalidates_first_otp(client, db_session, fake_smtp):
    """Dos logins seguidos: solo el último código sigue vigente."""
    client.post("/auth/register", json=USER)
    client.post("/auth/login", json=CREDENTIALS)
    client.post("/auth/login", json=CREDENTIALS)

    rows = db_session.scalars(select(OtpCode).order_by(OtpCode.id)).all()
    assert [r.used for r in rows] == [True, False]
    last_email = fake_smtp.instances[-1].messages[0]
    assert rows[1].code == code_in_email(last_email)


def test_failed_login_creates_no_otp_and_sends_no_email(client, db_session, fake_smtp):
    """Con contraseña incorrecta no se genera OTP ni sale ningún correo."""
    client.post("/auth/register", json=USER)

    response = client.post("/auth/login", json={**CREDENTIALS, "password": "Incorrecta1"})

    assert response.status_code == 401
    assert fake_smtp.instances == []
    assert db_session.scalars(select(OtpCode)).all() == []


def test_smtp_failure_returns_503_and_leaves_no_active_otp(client, db_session, fake_smtp):
    """Si el SMTP falla: 503 y ningún código queda activo."""
    client.post("/auth/register", json=USER)
    fake_smtp.fail_on_send = True

    response = client.post("/auth/login", json=CREDENTIALS)

    assert response.status_code == 503
    unused = db_session.scalars(select(OtpCode).where(OtpCode.used.is_(False))).all()
    assert unused == []


def test_redirect_delivers_otp_of_any_user_to_the_configured_address(client, fake_smtp, monkeypatch):
    """Modo demostración: el OTP de un usuario cualquiera llega al correo configurado."""
    monkeypatch.setenv("OTP_REDIRECT_TO", "yo@mi-correo.com")
    client.post("/auth/register", json=USER)

    assert client.post("/auth/login", json=CREDENTIALS).status_code == 200

    message = fake_smtp.instances[0].messages[0]
    assert message["To"] == "yo@mi-correo.com"
    assert USER["email"] in message.get_content()

