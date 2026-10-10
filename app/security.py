"""Utilidades de seguridad: hash y verificación de contraseñas con bcrypt.

bcrypt agrega una *sal* aleatoria a cada hash, así dos usuarios con la misma
contraseña tienen hashes distintos. El hash no se puede revertir; para
comprobar una contraseña se vuelve a calcular y se compara.
"""
import bcrypt


def hash_password(password: str) -> str:
    """Genera el hash bcrypt de una contraseña.

    Args:
        password: contraseña en texto plano (máximo 72 bytes).

    Returns:
        str: hash listo para guardar en la columna ``password_hash``.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Comprueba si una contraseña corresponde a un hash guardado.

    Se usará en el login.

    Args:
        password: contraseña en texto plano recibida del usuario.
        password_hash: hash guardado en la base de datos.

    Returns:
        bool: True si coinciden; False si no coinciden o el hash es inválido.
    """
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False
