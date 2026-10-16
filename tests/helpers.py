"""Utilidades compartidas por los tests."""
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from sqlalchemy.orm import Session

from app.middleware import JWT_ALGORITHM, JWT_SECRET
from app.models import LoginSession, User


def make_token(db: Session, user: User, minutes: int = 30) -> str:
    """Emite un JWT para ``user`` y registra su sesión activa en ``login_sessions``.

    Replica lo que hará ``/auth/verify-otp``: sin la fila de sesión el
    middleware rechaza el token.
    """
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=minutes)
    token = jwt.encode(
        {"sub": str(user.id), "exp": expires_at, "jti": uuid.uuid4().hex},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )
    db.add(LoginSession(user_id=user.id, token=token, expires_at=expires_at))
    db.commit()
    return token