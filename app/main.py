"""Punto de entrada de la aplicación FastAPI.

Aquí se crea la instancia de la app y se registran los routers.
Para ejecutarla en desarrollo:

    uvicorn app.main:app --reload
"""
from fastapi import FastAPI

from app.routes import auth, users

app = FastAPI(
    title="Sistema de Autenticación con OTP",
    description="API de autenticación con usuario/contraseña y OTP por correo.",
    version="0.1.0",
)

# Routers de cada módulo (hoy vacíos; se llenan por feature/rama).
app.include_router(auth.router)
app.include_router(users.router)


@app.get("/health", tags=["health"])
def health_check() -> dict:
    """Verifica que la API está arriba.

    Returns:
        dict: ``{"status": "ok"}`` si el servicio responde.
    """
    return {"status": "ok"}
