"""
tests/conftest.py – pytest configuration and shared fixtures.

IMPORTANT: env vars must be set BEFORE any app module is imported,
because app/config.py reads them at import time (after load_dotenv()).
"""
import os

# ── Inject test environment FIRST ────────────────────────────────────────────
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_crice.db")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-32ch!")
os.environ.setdefault("CSRF_SECRET", "test-csrf-secret-not-for-production-32!")
os.environ.setdefault("SECURE_COOKIES", "false")

# ── Now import app modules ────────────────────────────────────────────────────
import secrets

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.auth.password import hash_password
from app.auth.sessions import create_session_token, load_session_token
from app.db import Base, get_db
from app.main import app
from app.models import (
    Case,
    PurposeEnum,
    StageEnum,
    SubjectType,
    User,
    UserRole,
)

# ── Test database ─────────────────────────────────────────────────────────────
_TEST_DB_URL = "sqlite:///./test_crice.db"


@pytest.fixture(scope="session")
def engine():
    eng = create_engine(_TEST_DB_URL, connect_args={"check_same_thread": False})

    @event.listens_for(eng, "connect")
    def _set_fk(dbapi_conn, _record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture(scope="function")
def db(engine):
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    yield session
    session.rollback()
    for table in reversed(Base.metadata.sorted_tables):
        session.execute(table.delete())
    session.commit()
    session.close()


@pytest.fixture(scope="function")
def client(db):
    def _override():
        yield db

    app.dependency_overrides[get_db] = _override
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


# ── Helper factories ──────────────────────────────────────────────────────────


def make_user(
    db,
    email: str = "op@crice.test",
    full_name: str = "Test Operator",
    role: UserRole = UserRole.operator,
    mfa_enabled: bool = True,
    is_active: bool = True,
    password: str = "Password1!",
) -> User:
    user = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(password),
        role=role,
        totp_secret=pyotp.random_base32(),
        mfa_enabled=mfa_enabled,
        is_active=is_active,
        failed_logins=0,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def make_case(
    db,
    operator: User,
    subject_type: SubjectType = SubjectType.company,
    stage: StageEnum = StageEnum.INTAKE,
    intake_approved: bool = True,
    reviewer: User | None = None,
) -> Case:
    case = Case(
        case_ref=f"CRICE-{secrets.token_hex(4).upper()}",
        client_name="Test Client Ltd",
        purpose=PurposeEnum.corporate_due_diligence,
        subject_type=subject_type,
        subject_name="Target Corp",
        stage=stage,
        intake_approved=intake_approved,
        operator_id=operator.id,
        reviewer_id=reviewer.id if reviewer else None,
        created_by=operator.id,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def session_cookies(user_id: int, mfa_ok: bool = True) -> dict[str, str]:
    """Return a cookies dict carrying a valid signed session token."""
    token = create_session_token(user_id, mfa_ok=mfa_ok)
    return {"session": token}


def csrf_token_for(cookies: dict[str, str]) -> str:
    """Extract the CSRF token embedded in the session cookie."""
    data = load_session_token(cookies["session"])
    return data["csrf"]
