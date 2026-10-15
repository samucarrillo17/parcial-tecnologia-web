"""Endpoints de usuarios: ver y actualizar perfil (protegidos por JWT)."""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware import get_current_user
from app.models import User
from app.schemas import UserResponse, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/profile",
    response_model=UserResponse,
    summary="Ver perfil del usuario autenticado",
    responses={
        401: {"description": "No autenticado o token inválido"},
    },
)
def get_profile(current_user: User = Depends(get_current_user)) -> User:
    """Retorna los datos públicos del usuario autenticado actual.

    Args:
        current_user: usuario extraído y validado del token JWT mediante middleware.

    Returns:
        User: datos del usuario serializados en UserResponse.
    """
    return current_user


@router.put(
    "/profile",
    response_model=UserResponse,
    summary="Actualizar perfil del usuario autenticado",
    responses={
        400: {"description": "No se enviaron campos para actualizar"},
        409: {"description": "El nuevo email ya está registrado por otro usuario"},
        422: {"description": "Datos de entrada inválidos"},
        401: {"description": "No autenticado"},
    },
)
def update_profile(
    payload: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """Actualiza el nombre completo y/o el correo del usuario autenticado.

    Args:
        payload: campos opcionales a modificar (full_name, email).
        current_user: usuario autenticado actual.
        db: sesión de base de datos.

    Returns:
        User: perfil actualizado.

    Raises:
        HTTPException: 400 si no se envía ningún cambio; 409 si el email ya existe.
    """
    update_data = {
        k: v for k, v in payload.model_dump(exclude_unset=True).items() if v is not None
    }
    if not update_data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No se proporcionaron datos para actualizar",
        )

    for key, value in update_data.items():
        setattr(current_user, key, value)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="El email ya está registrado por otro usuario",
        )

    db.refresh(current_user)
    return current_user