"""Configuración de la base de datos (SQLite + SQLAlchemy).

Define el *engine* (la conexión), la fábrica de sesiones, la clase ``Base``
de la que heredan todos los modelos y la dependencia ``get_db`` que FastAPI
inyecta en los endpoints.
"""
import os
from typing import Generator

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

# Lee las variables del archivo .env (si existe).
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./app.db")

# SQLite solo permite usar una conexión en el hilo que la creó. FastAPI atiende
# peticiones en varios hilos, por eso se desactiva esa comprobación (solo SQLite).
_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    """Clase base de la que heredan todos los modelos SQLAlchemy."""


def get_db() -> Generator[Session, None, None]:
    """Entrega una sesión de BD por petición y la cierra al terminar.

    Se usa en los endpoints con ``db: Session = Depends(get_db)``.

    Yields:
        Session: sesión de SQLAlchemy lista para consultar o guardar.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
