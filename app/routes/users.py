"""Endpoints de usuarios.

Pendientes: GET /users/profile, PUT /users/profile
"""
from fastapi import APIRouter

router = APIRouter(prefix="/users", tags=["users"])
