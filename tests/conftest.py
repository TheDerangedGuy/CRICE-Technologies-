"""
tests/conftest.py – pytest configuration and shared fixtures.

IMPORTANT: env vars must be set BEFORE any app module is imported,
because app/config.py reads them at import time (after load_dotenv()).
"""
import os

# ── Inject test environment FIRST ────────────────────────────────────────────
os.environ["DATABASE_URL"] = "sqlite:///./test_crice.db"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production-32ch!"
# Valid Fernet key for tests (deterministic; never used in production)
os.environ["TOTP_ENCRYPTION_KEY"] = "bENUKm7bq0ztcgT0j9LFr5TRxaFbWNjJ0uqIfakpE3M="
os.environ["SECURE_COOKIES"] = "false"
os.environ["SESSION_IDLE_SECONDS"] = "28800"
os.environ["SESSION_ABSOLUTE_SECONDS"] = "86400"

# ── Now import app modules ────────────────────────────────────────────────────
import secrets

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.auth.password import hash_password
from app.auth.sessions import create_session, COOKIE_NAME
from app.auth.totp_crypto import encrypt_totp_secret
from app.db import Base, get_db
from app.main import app
from app.models import (
    Case,
    PurposeEnum,
    Session as SessionModel,
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
    password: str = "Password1!TestLong",
) -> User:
    totp_plain = pyotp.random_base32()
    user = User(
        email=email,
        full_name=full_name,
        password_hash=hash_password(password),
        role=role.value,
        totp_secret_enc=encrypt_totp_secret(totp_plain) if mfa_enabled else None,
        mfa_enabled=mfa_enabled,
        is_active=is_active,
        failed_logins=0,
    )
    # Store plaintext TOTP for test assertions
    user._totp_plain = totp_plain  # type: ignore[attr-defined]
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
        purpose=PurposeEnum.corporate_due_diligence.value,
        subject_type=subject_type.value,
        subject_name="Target Corp",
        stage=stage.value,
        intake_approved=intake_approved,
        operator_id=operator.id,
        reviewer_id=reviewer.id if reviewer else None,
        created_by=operator.id,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


def make_session(db, user: User, mfa_verified: bool = True) -> tuple[SessionModel, dict]:
    """
    Create a server-side session row and return (row, cookies_dict).
    The cookies dict is ready to pass to TestClient as cookies=…
    """
    session_id, csrf = create_session(db, user.id, mfa_verified=mfa_verified)
    row = db.query(SessionModel).filter(SessionModel.session_id == session_id).first()
    return row, {COOKIE_NAME: session_id}


def csrf_token_for(row: SessionModel) -> str:
    """Return the CSRF token stored on the session row."""
    return row.csrf_token
