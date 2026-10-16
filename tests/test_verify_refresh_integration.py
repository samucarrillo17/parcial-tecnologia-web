"""Tests de INTEGRACIÓN de POST /auth/verify-otp y POST /auth/refresh.

Se recorre el flujo real: registro -> login -> verify-otp -> ruta protegida ->
refresh. Solo se simula el envío del correo (se captura el código en una lista).
"""
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from sqlalchemy import select

from app.middleware import JWT_ALGORITHM, JWT_SECRET
from app.models import OtpCode

USER = {"email": "ana.perez@gmail.com", "password": "Segura123", "full_name": "Ana Pérez"}
CREDENTIALS = {"email": USER["email"], "password": USER["password"]}


@pytest.fixture()
def sent_codes(monkeypatch):
    """Reemplaza send_otp por una función que guarda los códigos enviados."""
    codes: list[str] = []
    monkeypatch.setattr("app.routes.auth.send_otp", lambda email, code: codes.append(code))
    return codes


@pytest.fixture()
def logged_in_code(client, sent_codes) -> str:
    """Registra a Ana, hace login y devuelve el OTP que 'llegó' al correo."""
    assert client.post("/auth/register", json=USER).status_code == 201
    assert client.post("/auth/login", json=CREDENTIALS).status_code == 200
    return sent_codes[-1]


def verify(client, code: str, email: str = USER["email"]):
    """Llama a POST /auth/verify-otp."""
    return client.post("/auth/verify-otp", json={"email": email, "code": code})


def bearer(token: str) -> dict:
    """Arma el header Authorization."""
    return {"Authorization": f"Bearer {token}"}


def test_full_flow_login_verify_profile(client, logged_in_code):
    """Con el OTP correcto se obtiene un JWT que abre una ruta protegida."""
    response = verify(client, logged_in_code)

    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0
    profile = client.get("/users/profile", headers=bearer(body["access_token"]))
    assert profile.status_code == 200
    assert profile.json()["email"] == USER["email"]


def test_verify_otp_wrong_code_returns_401(client, logged_in_code):
    """Un código incorrecto da 401 y no entrega token."""
    wrong = "000000" if logged_in_code != "000000" else "111111"

    response = verify(client, wrong)

    assert response.status_code == 401
    assert "access_token" not in response.text


def test_verify_otp_code_cannot_be_reused(client, logged_in_code):
    """El OTP es de un solo uso: la segunda verificación da 401."""
    assert verify(client, logged_in_code).status_code == 200

    assert verify(client, logged_in_code).status_code == 401


def test_verify_otp_expired_code_returns_401(client, db_session, logged_in_code):
    """Un OTP expirado da 401."""
    row = db_session.scalar(select(OtpCode))
    row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    db_session.commit()

    assert verify(client, logged_in_code).status_code == 401


def test_verify_otp_unknown_email_returns_same_401(client, logged_in_code):
    """Un email inexistente da el mismo 401 (no revela qué correos existen)."""
    wrong_code = verify(client, "000000" if logged_in_code != "000000" else "111111")
    unknown_email = verify(client, logged_in_code, email="nadie@gmail.com")

    assert unknown_email.status_code == 401
    assert unknown_email.json() == wrong_code.json()


@pytest.mark.parametrize("bad_code", ["12345", "1234567", "abcdef", ""])
def test_verify_otp_malformed_code_returns_422(client, bad_code):
    """Un código que no son 6 dígitos se rechaza con 422."""
    assert verify(client, bad_code).status_code == 422


def test_refresh_returns_new_working_token(client, logged_in_code):
    """Refresh con un token válido entrega otro token distinto y funcional."""
    old_token = verify(client, logged_in_code).json()["access_token"]

    response = client.post("/auth/refresh", headers=bearer(old_token))

    assert response.status_code == 200
    new_token = response.json()["access_token"]
    assert new_token != old_token
    assert client.get("/users/profile", headers=bearer(new_token)).status_code == 200


def test_refresh_without_token_is_rejected(client):
    """Sin token no se puede refrescar (401, o 403 según la versión de FastAPI)."""
    assert client.post("/auth/refresh").status_code in (401, 403)


def test_refresh_with_expired_token_returns_401(client, logged_in_code):
    """Un token ya vencido no se puede refrescar."""
    user_id = client.get(
        "/users/profile", headers=bearer(verify(client, logged_in_code).json()["access_token"])
    ).json()["id"]
    expired = jwt.encode(
        {"sub": str(user_id), "exp": datetime.now(timezone.utc) - timedelta(minutes=1)},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    assert client.post("/auth/refresh", headers=bearer(expired)).status_code == 401