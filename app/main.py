"""Punto de entrada de la aplicación FastAPI.

Aquí se crea la instancia de la app, se registran los routers, el manejo de
errores y el rate limiting. Para ejecutarla en desarrollo:

    python -m uvicorn app.main:app --reload
"""
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app import models  # noqa: F401  (importarlo registra las tablas en Base)
from app.database import Base, engine
from app.rate_limit import limiter
from app.routes import auth, users


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Al arrancar la app, crea las tablas que aún no existan en la BD."""
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="Sistema de Autenticación con OTP",
    description="API de autenticación con usuario/contraseña y OTP por correo.",
    version="0.1.0",
    lifespan=lifespan,
)

# Rate limiting: responde 429 cuando se superan los intentos permitidos.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Responde 422 sin devolver el valor enviado por el cliente.

    Por defecto FastAPI incluye el campo ``input`` en cada error, y en un
    registro eso sería la contraseña en texto plano. Aquí solo se devuelve
    dónde falló y por qué.
    """
    errors = [{"loc": e["loc"], "msg": e["msg"], "type": e["type"]} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


# Routers de cada módulo.
app.include_router(auth.router)
app.include_router(users.router)


@app.get("/health", tags=["health"])
def health_check() -> dict:
    """Verifica que la API está arriba.

    Returns:
        dict: ``{"status": "ok"}`` si el servicio responde.
    """
    return {"status": "ok"}
