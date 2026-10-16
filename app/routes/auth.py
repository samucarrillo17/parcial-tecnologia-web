"""Endpoints de autenticación.

Implementados: POST /auth/register, /auth/login, /auth/verify-otp,
    /auth/refresh, /auth/logout y /auth/resend-otp
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.middleware import get_current_user, security
from app.models import LoginSession, OtpCode, User
from app.rate_limit import limiter
from app.schemas import (
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    RegisterRequest,
    ResendOtpRequest,
    ResendOtpResponse,
    TokenResponse,
    UserResponse,
    VerifyOtpRequest,
)
from app.security import DUMMY_HASH, hash_password, verify_password
from app.services.email_service import EmailDeliveryError, send_otp
from app.services.otp_service import (
    OTP_EXPIRE_MINUTES,
    generate_otp,
    invalidate_user_codes,
    verify_otp,
)
from app.services.token_service import create_session_token

router = APIRouter(prefix="/auth", tags=["auth"])


# Segundos mínimos entre dos reenvíos de OTP al mismo usuario (evita el spam de correos).
RESEND_COOLDOWN_SECONDS = 60


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


@router.post(
    "/resend-otp",
    response_model=ResendOtpResponse,
    summary="Reenviar el código OTP al correo",
    responses={
        422: {"description": "Datos de entrada inválidos"},
        429: {"description": "Demasiados intentos, espera un momento"},
        503: {"description": "No se pudo enviar el correo con el OTP"},
    },
)
@limiter.limit("3/minute")
def resend_otp(
    request: Request,  # slowapi lo necesita para identificar la IP del cliente
    payload: ResendOtpRequest,
    db: Session = Depends(get_db),
) -> ResendOtpResponse:
    """Genera un OTP nuevo y lo envía de nuevo al correo del usuario.

    Medidas de seguridad:
        - La respuesta es idéntica (200) exista o no el correo, para no
          revelar qué correos están registrados.
        - Rate limit por IP (3 por minuto) y una espera de
          ``RESEND_COOLDOWN_SECONDS`` entre reenvíos al mismo usuario; dentro
          de esa espera no se envía nada y el código anterior sigue vigente.
        - Al generar el código nuevo, los anteriores quedan invalidados.

    Args:
        request: petición HTTP (usada por el rate limiter).
        payload: correo del usuario.
        db: sesión de base de datos inyectada por FastAPI.

    Returns:
        ResendOtpResponse: mensaje genérico y minutos de vigencia del código.

    Raises:
        HTTPException: 503 si el correo no pudo enviarse.
    """
    response = ResendOtpResponse(
        message="Si el correo está registrado, te enviamos un código de verificación",
        expires_in_minutes=OTP_EXPIRE_MINUTES,
    )

    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None:
        return response

    # Cooldown: si el último código se generó hace muy poco, no se envía otro.
    last_code = db.scalar(
        select(OtpCode).where(OtpCode.user_id == user.id).order_by(OtpCode.id.desc())
    )
    if last_code is not None:
        created_at = last_code.created_at
        if created_at.tzinfo is None:  # SQLite devuelve las fechas sin zona horaria
            created_at = created_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) - created_at < timedelta(seconds=RESEND_COOLDOWN_SECONDS):
            return response

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
    return response


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Cerrar sesión y revocar el token actual",
    responses={
        401: {"description": "No autenticado, token inválido o sesión ya cerrada"},
    },
)
def logout(
    current_user: User = Depends(get_current_user),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> LogoutResponse:
    """Cierra la sesión: elimina el token actual de ``login_sessions``.

    Desde ese momento el middleware rechaza el token con 401, aunque su fecha
    de expiración todavía no haya llegado. Solo se revoca el token con el que
    se hizo la petición; otras sesiones del usuario siguen activas.

    Args:
        current_user: usuario autenticado (el middleware ya validó el token).
        credentials: header ``Authorization: Bearer <token>`` de la petición.
        db: sesión de base de datos inyectada por FastAPI.

    Returns:
        LogoutResponse: confirmación del cierre de sesión.
    """
    session = db.scalar(
        select(LoginSession).where(
            LoginSession.token == credentials.credentials,
            LoginSession.user_id == current_user.id,
        )
    )
    if session is not None:
        db.delete(session)
        db.commit()
    return LogoutResponse(message="Sesión cerrada correctamente")


@router.post(
    "/verify-otp",
    response_model=TokenResponse,
    summary="Verificar el OTP y obtener el JWT",
    responses={
        401: {"description": "Código inválido, expirado o ya usado"},
        422: {"description": "Datos de entrada inválidos"},
        429: {"description": "Demasiados intentos, espera un momento"},
    },
)
@limiter.limit("5/minute")
def verify_otp_endpoint(
    request: Request,  # slowapi lo necesita para identificar la IP del cliente
    payload: VerifyOtpRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Verifica el OTP enviado por correo y entrega el token JWT.

    Es el segundo paso del login: ``/auth/login`` valida la contraseña y envía
    el código; aquí se comprueba ese código y, si es correcto, se emite el JWT.
    El código se consume: no puede usarse dos veces.

    Args:
        request: petición HTTP (usada por el rate limiter).
        payload: email y código de 6 dígitos.
        db: sesión de base de datos inyectada por FastAPI.

    Returns:
        TokenResponse: token JWT, tipo ``bearer`` y segundos de vigencia.

    Raises:
        HTTPException: 401 si el código es incorrecto, expiró, ya se usó o el
            email no existe (siempre el mismo mensaje, para no revelar cuál).
    """
    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Código inválido o expirado",
    )

    user = db.scalar(select(User).where(User.email == payload.email))
    if user is None or not verify_otp(db, user, payload.code):
        raise invalid

    token, expires_in = create_session_token(db, user.id)
    return TokenResponse(access_token=token, expires_in=expires_in)


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refrescar el token JWT",
    responses={
        401: {"description": "No autenticado, token inválido o expirado"},
        429: {"description": "Demasiados intentos, espera un momento"},
    },
)
@limiter.limit("10/minute")
def refresh_token(
    request: Request,  # slowapi lo necesita para identificar la IP del cliente
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Emite un JWT nuevo para el usuario autenticado.

    Requiere un token todavía vigente en ``Authorization: Bearer <token>``:
    ``get_current_user`` ya lo validó (firma y expiración) antes de entrar aquí.
    El token nuevo trae una expiración renovada.

    Args:
        request: petición HTTP (usada por el rate limiter).
        current_user: usuario dueño del token actual, entregado por el middleware.
        db: sesión de base de datos inyectada por FastAPI.

    Returns:
        TokenResponse: token JWT nuevo, tipo ``bearer`` y segundos de vigencia.

    Raises:
        HTTPException: 401 (lanzada por el middleware) si el token falta, es
            inválido o ya expiró.
    """
    token, expires_in = create_session_token(db, current_user.id)
    return TokenResponse(access_token=token, expires_in=expires_in)
