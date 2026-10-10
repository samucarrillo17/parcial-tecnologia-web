"""Tests unitarios de app/security.py (hash de contraseñas)."""
from app.security import hash_password, verify_password


def test_hash_is_not_plain_text_and_verifies():
    """El hash no es la contraseña original y verify_password lo acepta."""
    hashed = hash_password("Segura123")

    assert hashed != "Segura123"
    assert verify_password("Segura123", hashed) is True


def test_verify_password_rejects_wrong_password():
    """Una contraseña incorrecta no verifica contra el hash."""
    hashed = hash_password("Segura123")

    assert verify_password("OtraClave456", hashed) is False


def test_same_password_gives_different_hashes():
    """Por la sal aleatoria, la misma contraseña genera hashes distintos."""
    assert hash_password("Segura123") != hash_password("Segura123")
