"""Endpoints de autenticación.

Pendientes (sección 5 del parcial):
    POST /auth/register, /auth/login, /auth/verify-otp,
    /auth/refresh, /auth/logout, /auth/resend-otp
"""
from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])
