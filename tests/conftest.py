"""Fixtures compartidas por todos los tests.

Cada test recibe una base de datos SQLite en memoria, nueva y vacía, así los
tests no se afectan entre sí ni tocan el archivo app.db real.
"""
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import models  # noqa: F401  (registra las tablas en Base)
from app.database import Base, get_db
from app.main import app as fastapi_app
from app.rate_limit import limiter


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    """Sesión sobre una BD SQLite en memoria con todas las tablas creadas."""
    # StaticPool: todas las conexiones comparten la misma BD en memoria.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = testing_session()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """Cliente de pruebas que usa la BD en memoria y con rate limiting apagado."""

    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    fastapi_app.dependency_overrides[get_db] = override_get_db
    limiter.enabled = False
    limiter.reset()
    yield TestClient(fastapi_app)
    fastapi_app.dependency_overrides.clear()
    limiter.enabled = True
    limiter.reset()
