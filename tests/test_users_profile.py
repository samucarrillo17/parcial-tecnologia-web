"""Tests de integración para los endpoints /users/profile (GET y PUT)."""
from app.models import User
from app.security import hash_password
from tests.helpers import make_token


def test_get_profile_success(client, db_session):
    """GET /users/profile con token válido retorna los datos del usuario."""
    user = User(email="perfil@gmail.com", password_hash=hash_password("Segura123"), full_name="Carlos Test")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    # Creamos el token usando los mismos parámetros del middleware
    token = make_token(db_session, user)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/users/profile", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "perfil@gmail.com"
    assert data["full_name"] == "Carlos Test"
    assert "password_hash" not in data


def test_get_profile_unauthorized_without_token(client):
    """GET /users/profile sin token de autorización retorna 401 o 403."""
    response = client.get("/users/profile")
    assert response.status_code in (401, 403)


def test_update_profile_success(client, db_session):
    """PUT /users/profile actualiza correctamente el nombre y correo."""
    user = User(email="viejo@gmail.com", password_hash=hash_password("Segura123"), full_name="Nombre Viejo")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = make_token(db_session, user)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.put(
        "/users/profile",
        json={"full_name": "Nombre Nuevo", "email": "nuevo@gmail.com"},
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["full_name"] == "Nombre Nuevo"
    assert data["email"] == "nuevo@gmail.com"


def test_update_profile_duplicate_email_conflict(client, db_session):
    """PUT /users/profile con un email ya existente de otro usuario da 409."""
    user1 = User(email="user1@gmail.com", password_hash=hash_password("Segura123"), full_name="User One")
    user2 = User(email="user2@gmail.com", password_hash=hash_password("Segura123"), full_name="User Two")
    db_session.add_all([user1, user2])
    db_session.commit()
    db_session.refresh(user1)
    db_session.refresh(user2)

    token = make_token(db_session, user1)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.put("/users/profile", json={"email": "user2@gmail.com"}, headers=headers)
    assert response.status_code == 409


def test_update_profile_empty_body_bad_request(client, db_session):
    """PUT /users/profile sin campos responde 400 Bad Request."""
    user = User(email="test@gmail.com", password_hash=hash_password("Segura123"), full_name="Test")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = make_token(db_session, user)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.put("/users/profile", json={}, headers=headers)
    assert response.status_code == 400

def test_update_profile_null_fields_bad_request(client, db_session):
    """PUT /users/profile con campos null se trata como body vacío (400)."""
    user = User(email="nulo@gmail.com", password_hash=hash_password("Segura123"), full_name="Nulo")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = make_token(db_session, user)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.put("/users/profile", json={"email": None}, headers=headers)
    assert response.status_code == 400


def test_update_profile_invalid_email_format(client, db_session):
    """PUT /users/profile con un email mal formado responde 422."""
    user = User(email="fmt@gmail.com", password_hash=hash_password("Segura123"), full_name="Fmt")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = make_token(db_session, user)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.put("/users/profile", json={"email": "no-es-un-correo"}, headers=headers)
    assert response.status_code == 422


def test_get_profile_invalid_token(client):
    """GET /users/profile con un token basura responde 401."""
    response = client.get("/users/profile", headers={"Authorization": "Bearer token.falso.xyz"})
    assert response.status_code == 401