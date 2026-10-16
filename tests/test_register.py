"""Tests de POST /auth/register."""
import pytest
from sqlalchemy import select

from app.models import User
from app.rate_limit import limiter

VALID_USER = {
    "email": "joshua.nieto@gmail.com",
    "password": "Segura123",
    "full_name": "Ana Pérez",
}


def test_register_success(client):
    """Un registro válido responde 201 y no devuelve contraseña ni hash."""
    response = client.post("/auth/register", json=VALID_USER)

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "joshua.nieto@gmail.com"
    assert body["full_name"] == "Ana Pérez"
    assert "id" in body and "created_at" in body
    assert "password" not in body
    assert "password_hash" not in body


def test_register_stores_hashed_password(client, db_session):
    """En la BD se guarda el hash bcrypt, nunca la contraseña en texto plano."""
    client.post("/auth/register", json=VALID_USER)

    user = db_session.scalar(select(User).where(User.email == VALID_USER["email"]))
    assert user is not None
    assert user.password_hash != VALID_USER["password"]
    assert user.password_hash.startswith("$2")  # prefijo de los hashes bcrypt


def test_register_duplicate_email_returns_409(client):
    """Registrar dos veces el mismo email (aunque cambie la capitalización) da 409."""
    client.post("/auth/register", json=VALID_USER)
    repeated = {**VALID_USER, "email": "ANA.PEREZ@gmail.com"}

    response = client.post("/auth/register", json=repeated)

    assert response.status_code == 409


def test_register_invalid_email_returns_422(client):
    """Un email mal formado se rechaza con 422."""
    response = client.post("/auth/register", json={**VALID_USER, "email": "no-es-un-email"})

    assert response.status_code == 422


@pytest.mark.parametrize(
    "weak_password",
    [
        "Corta1",  # menos de 8 caracteres
        "sinmayuscula1",  # sin mayúscula
        "SINMINUSCULA1",  # sin minúscula
        "SinNumeroAqui",  # sin número
    ],
)
def test_register_weak_password_returns_422(client, weak_password):
    """Las contraseñas que incumplen las reglas se rechazan con 422."""
    response = client.post("/auth/register", json={**VALID_USER, "password": weak_password})

    assert response.status_code == 422


def test_register_empty_name_returns_422(client):
    """Un nombre compuesto solo por espacios se rechaza con 422."""
    response = client.post("/auth/register", json={**VALID_USER, "full_name": "   "})

    assert response.status_code == 422


def test_register_validation_error_does_not_echo_password(client):
    """El error 422 no debe devolver la contraseña enviada por el cliente."""
    response = client.post("/auth/register", json={**VALID_USER, "password": "sinmayuscula1"})

    assert response.status_code == 422
    assert "sinmayuscula1" not in response.text


def test_register_rate_limit_returns_429(client):
    """Tras 5 registros en un minuto, el sexto recibe 429."""
    limiter.enabled = True  # el fixture lo apaga; aquí sí lo necesitamos
    limiter.reset()

    statuses = [
        client.post("/auth/register", json={**VALID_USER, "email": f"user{i}@gmail.com"}).status_code
        for i in range(6)
    ]

    assert statuses[:5] == [201] * 5
    assert statuses[5] == 429
