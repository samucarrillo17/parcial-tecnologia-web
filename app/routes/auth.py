"""Endpoints de autenticación.

Implementados: POST /auth/register, POST /auth/login
Pendientes (sección 5 del parcial):
    POST /auth/verify-otp, /auth/refresh, /auth/logout, /auth/resend-otp
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.rate_limit import limiter
from app.schemas import LoginRequest, LoginResponse, RegisterRequest, UserResponse
from app.security import DUMMY_HASH, hash_password, verify_password
from app.services.email_service import EmailDeliveryError, send_otp
from app.services.otp_service import OTP_EXPIRE_MINUTES, generate_otp, invalidate_user_codes

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
    request: Request,  # slowapi lo necesita para identificar la IP del cliente
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


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Iniciar sesión y recibir un OTP por correo",
    responses={
        401: {"description": "Credenciales inválidas"},
        422: {"description": "Datos de entrada inválidos"},
        429: {"description": "Demasiados intentos, espera un momento"},
        503: {"description": "No se pudo enviar el correo con el OTP"},
    },
)
@limiter.limit("5/minute")
def login(
    request: Request,  # slowapi lo necesita para identificar la IP del cliente
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> LoginResponse:
    """Valida email y contraseña y envía un OTP de 6 dígitos al correo.

    Este endpoint NO entrega el JWT: el token se obtiene después, al verificar
    el OTP en ``/auth/verify-otp``.

    Args:
        request: petición HTTP (usada por el rate limiter).
        payload: email y contraseña.
        db: sesión de base de datos inyectada por FastAPI.

    Returns:
        LoginResponse: confirmación del envío y minutos de vigencia del código.

    Raises:
        HTTPException: 401 si el email o la contraseña no son correctos
            (mismo mensaje en ambos casos); 503 si el correo no pudo enviarse.
    """
    user = db.scalar(select(User).where(User.email == payload.email))

    # Se verifica SIEMPRE una contraseña (contra el hash real o contra uno
    # señuelo) para que la respuesta tarde igual exista o no el email.
    password_ok = verify_password(
        payload.password, user.password_hash if user else DUMMY_HASH
    )
    if user is None or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
        )

    code = generate_otp(db, user)
    try:
        send_otp(user.email, code)
    except EmailDeliveryError:
        # El usuario nunca recibió el código: se invalida para que no quede activo.
        invalidate_user_codes(db, user.id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No pudimos enviar el código de verificación. Intenta de nuevo más tarde",
        )

    return LoginResponse(
        message="Te enviamos un código de verificación a tu correo",
        expires_in_minutes=OTP_EXPIRE_MINUTES,
    )
