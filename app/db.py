"""
app/db.py – SQLAlchemy engine, session factory, and FastAPI dependency.
Engine creation is deferred so that tests can set DATABASE_URL before the
first import triggers a connection.
"""
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

import app.config as config


class Base(DeclarativeBase):
    """Shared declarative base; all ORM models inherit from this."""


_engine = None
_SessionLocal = None


def _get_engine():
    global _engine
    if _engine is None:
        if not config.DATABASE_URL:
            raise RuntimeError(
                "DATABASE_URL is not configured. "
                "Copy .env.example → .env and fill in the values."
            )
        _engine = create_engine(config.DATABASE_URL)
    return _engine


def _get_session_factory():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=_get_engine(),
        )
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency – yields a SQLAlchemy session and closes it after."""
    db: Session = _get_session_factory()()
    try:
        yield db
    finally:
        db.close()


def reset_engine() -> None:
    """Test helper: force a new engine on next call (use after swapping DATABASE_URL)."""
    global _engine, _SessionLocal
    _engine = None
    _SessionLocal = None
