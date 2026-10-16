"""Servicio de tokens JWT: creación del token de acceso y de su sesión.

La validación del token (y la obtención del usuario) vive en
``app/middleware.py``. Aquí se usan EXACTAMENTE los mismos ``JWT_SECRET`` y
``JWT_ALGORITHM`` que el middleware, para que un token creado aquí siempre
pueda ser leído allá.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy.orm import Session

from app.middleware import JWT_ALGORITHM, JWT_SECRET
from app.models import LoginSession

# Minutos de vigencia del token de acceso (configurable en .env).
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))


def create_access_token(user_id: int) -> tuple[str, int]:
    """Crea un JWT de acceso para un usuario.

    El token incluye estos claims:
        - ``sub``: id del usuario (como texto; así lo exige el estándar JWT).
        - ``iat``: momento de emisión.
        - ``exp``: momento de expiración (obligatorio según el parcial).
        - ``jti``: identificador único del token. Hace que dos tokens emitidos
          en el mismo segundo sean distintos y permitirá revocarlos por id.

    Args:
        user_id: id del usuario dueño del token.

    Returns:
        tuple[str, int]: el token firmado y su vigencia en segundos.
    """
    now = datetime.now(timezone.utc)
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + expires_delta,
        "jti": uuid.uuid4().hex,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token, int(expires_delta.total_seconds())


def create_session_token(db: Session, user_id: int) -> tuple[str, int]:
    """Crea un JWT y registra su sesión activa en ``login_sessions``.

    El middleware solo acepta un token si existe su fila en ``login_sessions``
    (así ``/auth/logout`` puede revocarlo). Por eso todo token que se entrega
    al usuario (verify-otp y refresh) debe emitirse con esta función y no con
    ``create_access_token`` a secas.

    Args:
        db: sesión de base de datos.
        user_id: id del usuario dueño del token.

    Returns:
        tuple[str, int]: el token firmado y su vigencia en segundos.
    """
    token, expires_in = create_access_token(user_id)
    db.add(
        LoginSession(
            user_id=user_id,
            token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=expires_in),
        )
    )
    db.commit()
    return token, expires_in
