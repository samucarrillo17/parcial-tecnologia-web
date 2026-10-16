"""Tests unitarios de app/services/email_service.py (envío y desvío del OTP).

Solo se simula el servidor SMTP (smtplib.SMTP): se comprueba a quién se le
entregaría el correo y qué diría.
"""
import smtplib

import pytest

from app.services.email_service import EmailDeliveryError, send_otp


@pytest.fixture()
def smtp_outbox(monkeypatch):
    """SMTP falso con configuración válida; devuelve la lista de correos 'enviados'."""
    monkeypatch.setenv("EMAIL_BACKEND", "smtp")
    monkeypatch.setenv("SMTP_HOST", "smtp.prueba.local")
    monkeypatch.setenv("SMTP_USER", "remitente@prueba.local")
    monkeypatch.setenv("SMTP_PASSWORD", "clave-de-prueba")
    outbox: list = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc_info):
            return False

        def starttls(self):
            pass

        def login(self, user, password):
            pass

        def send_message(self, message):
            outbox.append(message)

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    return outbox


def test_otp_goes_to_the_user_by_default(smtp_outbox):
    """Sin OTP_REDIRECT_TO, el correo se entrega al email del usuario."""
    send_otp("ana@gmail.com", "123456")

    assert len(smtp_outbox) == 1
    assert smtp_outbox[0]["To"] == "ana@gmail.com"
    assert "123456" in smtp_outbox[0].get_content()
    assert "Modo demostración" not in smtp_outbox[0].get_content()


def test_redirect_sends_every_otp_to_the_configured_address(monkeypatch, smtp_outbox):
    """Con OTP_REDIRECT_TO, el correo va a esa dirección y el cuerpo dice para quién era."""
    monkeypatch.setenv("OTP_REDIRECT_TO", "yo@mi-correo.com")

    send_otp("ana@gmail.com", "123456")

    assert smtp_outbox[0]["To"] == "yo@mi-correo.com"
    body = smtp_outbox[0].get_content()
    assert "123456" in body
    assert "ana@gmail.com" in body


def test_blank_redirect_is_ignored(monkeypatch, smtp_outbox):
    """Un OTP_REDIRECT_TO vacío o con solo espacios no desvía nada."""
    monkeypatch.setenv("OTP_REDIRECT_TO", "   ")

    send_otp("ana@gmail.com", "123456")

    assert smtp_outbox[0]["To"] == "ana@gmail.com"


def test_missing_smtp_config_raises_delivery_error(monkeypatch):
    """Sin credenciales SMTP se lanza EmailDeliveryError (el login responde 503)."""
    monkeypatch.setenv("EMAIL_BACKEND", "smtp")

    with pytest.raises(EmailDeliveryError):
        send_otp("ana@gmail.com", "123456")
