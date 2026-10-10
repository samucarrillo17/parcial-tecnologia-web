"""Servicio de envío de correos por SMTP (librería estándar ``smtplib``).

Configuración (variables de entorno, ver ``.env.example``):
    EMAIL_BACKEND   "smtp" (por defecto) o "console" (solo desarrollo)
    SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM
"""
import logging
import os
import smtplib
from email.message import EmailMessage

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class EmailDeliveryError(Exception):
    """No se pudo entregar el correo (SMTP mal configurado o caído)."""


def send_otp(email: str, code: str) -> None:
    """Envía por correo el código OTP al usuario.

    Con ``EMAIL_BACKEND=console`` el código se imprime en la terminal en lugar
    de enviarse: sirve para desarrollar sin SMTP y NO debe usarse en producción.

    Args:
        email: correo destinatario.
        code: código OTP de 6 dígitos.

    Raises:
        EmailDeliveryError: si el SMTP no está configurado o falla el envío.
    """
    if os.getenv("EMAIL_BACKEND", "smtp").lower() == "console":
        print(f"[DEV] Código OTP para {email}: {code}")
        return

    host = os.getenv("SMTP_HOST")
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    sender = os.getenv("SMTP_FROM") or user
    port = int(os.getenv("SMTP_PORT", "587"))

    if not (host and user and password):
        logger.error("SMTP no configurado: faltan SMTP_HOST, SMTP_USER o SMTP_PASSWORD")
        raise EmailDeliveryError("SMTP no configurado")

    message = EmailMessage()
    message["Subject"] = "Tu código de verificación"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Tu código de verificación es: {code}\n\n"
        "Es válido por 15 minutos y solo puede usarse una vez.\n"
        "Si no intentaste iniciar sesión, ignora este correo."
    )

    try:
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.starttls()
            server.login(user, password)
            server.send_message(message)
    except (smtplib.SMTPException, OSError) as exc:
        # Se registra solo el tipo de error: nunca el código ni credenciales.
        logger.error("Falló el envío SMTP: %s", type(exc).__name__)
        raise EmailDeliveryError("No se pudo enviar el correo") from exc
