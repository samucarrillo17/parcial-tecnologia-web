"""Endpoints de autenticación.

Implementados: POST /auth/register
Pendientes (sección 5 del parcial):
    POST /auth/login, /auth/verify-otp, /auth/refresh, /auth/logout, /auth/resend-otp
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.rate_limit import limiter
from app.schemas import RegisterRequest, UserResponse
from app.security import hash_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar un nuevo usuario",
    responses={
        409: {"description": "El email ya está registrado"},
        422: {"description": "Datos de entrada inválidos"},
        429: {"description": "Demasiados intentos, espera un momento"},
    },
)
@limiter.limit("5/minute")
def register(
    request: Request,  
    payload: RegisterRequest,
    db: Session = Depends(get_db),
) -> User:
    """Crea una cuenta nueva.

    Valida los datos (Pydantic), verifica que el email no exista, hashea la
    contraseña con bcrypt y guarda el usuario.

    Args:
        request: petición HTTP (usada por el rate limiter).
        payload: email, contraseña y nombre completo ya validados.
        db: sesión de base de datos inyectada por FastAPI.

    Returns:
        User: usuario creado (se serializa como ``UserResponse``, sin contraseña).

    Raises:
        HTTPException: 409 si el email ya está registrado.
    """
    already_exists = db.scalar(select(User).where(User.email == payload.email))
    if already_exists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El email ya está registrado",
        )

    user = User(
        email=payload.email,
        password_hash=hash_password(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El email ya está registrado",
        )
    db.refresh(user)
    return user
