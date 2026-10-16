"""Tests de POST /auth/logout (revocación de token)."""
from sqlalchemy import select

from app.models import LoginSession, User
from app.security import hash_password
from tests.helpers import make_token


def make_user(db_session, email="ana@gmail.com") -> User:
    """Crea y guarda un usuario de prueba."""
    user = User(email=email, password_hash=hash_password("Segura123"), full_name="Ana")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def test_logout_returns_200_and_deletes_session(client, db_session):
    """Logout con token válido responde 200 y borra la sesión."""
    token = make_token(db_session, make_user(db_session))

    response = client.post("/auth/logout", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {"message": "Sesión cerrada correctamente"}
    assert db_session.scalars(select(LoginSession)).all() == []


def test_token_is_rejected_after_logout(client, db_session):
    """Integración: tras cerrar sesión, el mismo token ya no abre rutas protegidas."""
    headers = {"Authorization": f"Bearer {make_token(db_session, make_user(db_session))}"}
    assert client.get("/users/profile", headers=headers).status_code == 200

    assert client.post("/auth/logout", headers=headers).status_code == 200

    assert client.get("/users/profile", headers=headers).status_code == 401


def test_logout_twice_returns_401(client, db_session):
    """El segundo logout con el mismo token falla: la sesión ya no existe."""
    headers = {"Authorization": f"Bearer {make_token(db_session, make_user(db_session))}"}
    client.post("/auth/logout", headers=headers)

    assert client.post("/auth/logout", headers=headers).status_code == 401


def test_logout_without_token_is_rejected(client):
    """Sin header Authorization no se puede cerrar sesión (401 o 403)."""
    assert client.post("/auth/logout").status_code in (401, 403)


def test_logout_with_invalid_token_returns_401(client):
    """Un token basura responde 401."""
    response = client.post("/auth/logout", headers={"Authorization": "Bearer token.falso.xyz"})
    assert response.status_code == 401


def test_logout_only_revokes_current_session(client, db_session):
    """Si el usuario tiene dos sesiones, cerrar una no afecta a la otra."""
    user = make_user(db_session)
    token_a = make_token(db_session, user)
    token_b = make_token(db_session, user)

    client.post("/auth/logout", headers={"Authorization": f"Bearer {token_a}"})

    ok = client.get("/users/profile", headers={"Authorization": f"Bearer {token_b}"})
    assert ok.status_code == 200
    revoked = client.get("/users/profile", headers={"Authorization": f"Bearer {token_a}"})
    assert revoked.status_code == 401