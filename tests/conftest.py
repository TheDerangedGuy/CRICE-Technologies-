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
os.environ["CRICE_OFFLINE_RDAP"] = "1"

# ── Now import app modules ────────────────────────────────────────────────────
import datetime
import hashlib
import json
import secrets
from typing import Optional, Union

import pyotp
import pytest
from fastapi.testclient import TestClient
import sqlalchemy as sa
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.auth.password import hash_password
from app.auth.sessions import create_session, COOKIE_NAME
from app.auth.totp_crypto import encrypt_totp_secret
from app.collect.charter import seed_source_charter
from app.db import Base, get_db
from app.main import app
from app.models import (
    Case,
    CaseStage,
    CollectionMode,
    PurposeEnum,
    Record,
    Session as SessionModel,
    SourceCharter,
    SourceRun,
    SourceRunStatus,
    StageEnum,
    SubjectType,
    TriageStatus,
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
    with eng.begin() as conn:
        conn.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(FAIL, 'audit_log is append-only: UPDATE is forbidden');
            END;
        """))
        conn.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(FAIL, 'audit_log is append-only: DELETE is forbidden');
            END;
        """))
        conn.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_records_no_delete
            BEFORE DELETE ON records
            BEGIN
                SELECT RAISE(FAIL, 'records are immutable: DELETE is forbidden');
            END;
        """))
        conn.execute(sa.text("""
            CREATE TRIGGER IF NOT EXISTS trg_records_immutable_content
            BEFORE UPDATE ON records
            WHEN (OLD.raw_content != NEW.raw_content OR OLD.snapshot_hash != NEW.snapshot_hash OR OLD.source_url != NEW.source_url OR OLD.retrieved_at != NEW.retrieved_at)
            BEGIN
                SELECT RAISE(FAIL, 'record evidence is immutable: payload and hash cannot be modified');
            END;
        """))
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture(scope="function")
def db(engine):
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    seed_source_charter(session)
    yield session
    session.rollback()
    try:
        session.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_log_no_delete"))
        session.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_log_no_update"))
        session.execute(sa.text("DROP TRIGGER IF EXISTS trg_records_no_delete"))
        session.execute(sa.text("DROP TRIGGER IF EXISTS trg_records_immutable_content"))
    except Exception:
        pass
    for table in reversed(Base.metadata.sorted_tables):
        session.execute(table.delete())
    session.commit()
    try:
        session.execute(sa.text("""
            CREATE TRIGGER trg_audit_log_no_update
            BEFORE UPDATE ON audit_log
            BEGIN
                SELECT RAISE(FAIL, 'audit_log is append-only: UPDATE is forbidden');
            END;
        """))
        session.execute(sa.text("""
            CREATE TRIGGER trg_audit_log_no_delete
            BEFORE DELETE ON audit_log
            BEGIN
                SELECT RAISE(FAIL, 'audit_log is append-only: DELETE is forbidden');
            END;
        """))
        session.execute(sa.text("""
            CREATE TRIGGER trg_records_no_delete
            BEFORE DELETE ON records
            BEGIN
                SELECT RAISE(FAIL, 'records are immutable: DELETE is forbidden');
            END;
        """))
        session.execute(sa.text("""
            CREATE TRIGGER trg_records_immutable_content
            BEFORE UPDATE ON records
            WHEN (OLD.raw_content != NEW.raw_content OR OLD.snapshot_hash != NEW.snapshot_hash OR OLD.source_url != NEW.source_url OR OLD.retrieved_at != NEW.retrieved_at)
            BEGIN
                SELECT RAISE(FAIL, 'record evidence is immutable: payload and hash cannot be modified');
            END;
        """))
        session.commit()
    except Exception:
        pass
    session.close()


class CRICETestClient(TestClient):
    """TestClient subclass that sets cookies directly on the client instance to avoid HTTPX deprecation warnings."""

    def request(self, method, url, **kwargs):
        if "cookies" in kwargs and kwargs["cookies"] is not None:
            cookies = kwargs.pop("cookies")
            self.cookies.clear()
            self.cookies.update(cookies)
        return super().request(method, url, **kwargs)


@pytest.fixture(scope="function")
def client(db):
    def _override():
        yield db

    app.dependency_overrides[get_db] = _override
    with CRICETestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


_DEFAULT_TEST_PASSWORD = "Password1!TestLong"
_DEFAULT_PASSWORD_HASH = hash_password(_DEFAULT_TEST_PASSWORD)


def make_user(
    db,
    email: str = "op@crice.test",
    full_name: str = "Test Operator",
    role: UserRole = UserRole.operator,
    mfa_enabled: bool = True,
    is_active: bool = True,
    password: str = _DEFAULT_TEST_PASSWORD,
) -> User:
    totp_plain = pyotp.random_base32()
    pw_hash = _DEFAULT_PASSWORD_HASH if password == _DEFAULT_TEST_PASSWORD else hash_password(password)
    user = User(
        email=email,
        full_name=full_name,
        password_hash=pw_hash,
        role=role.value,
        totp_secret_enc=encrypt_totp_secret(totp_plain) if mfa_enabled else None,
        mfa_enabled=mfa_enabled,
        is_active=is_active,
        failed_logins=0,
    )
    user._totp_plain = totp_plain  # type: ignore[attr-defined]
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def make_case(
    db,
    operator: User,
    subject_type: SubjectType = SubjectType.company,
    stage: Union[CaseStage, str] = CaseStage.INTAKE_DRAFT,
    intake_approved: bool = False,
    client_name: str = "Test Client Ltd",
    client_kyc_verified: bool = True,
    msa_signed: bool = True,
    purpose: PurposeEnum = PurposeEnum.corporate_due_diligence,
    subject_name: str = "Target Corp",
    subject_identifier: Optional[str] = "U72200MH2018PTC123456",
    reviewer: Optional[User] = None,
    consent_verified: bool = False,
    dossier_version: int = 1,
    is_recalled: bool = False,
    rework_reason: Optional[str] = None,
) -> Case:
    stage_val = stage.value if isinstance(stage, CaseStage) else str(stage)
    case = Case(
        case_ref=f"CRICE-{secrets.token_hex(4).upper()}",
        client_name=client_name,
        client_kyc_verified=client_kyc_verified,
        msa_signed=msa_signed,
        purpose=purpose.value if isinstance(purpose, PurposeEnum) else purpose,
        subject_type=subject_type.value if isinstance(subject_type, SubjectType) else subject_type,
        subject_name=subject_name,
        subject_identifier=subject_identifier,
        stage=stage_val,
        intake_approved=intake_approved,
        consent_verified=consent_verified,
        dossier_version=dossier_version,
        is_recalled=is_recalled,
        rework_reason=rework_reason,
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


def make_source_run(
    db,
    case: Case,
    operator: User,
    source_code: str = "DOMAIN_RDAP",
    query_input: str = "acmetech.demo",
    status: str = "FOUND",
    error_detail: Optional[str] = None,
) -> SourceRun:
    """Create a source run row."""
    charter = db.query(SourceCharter).filter(SourceCharter.code == source_code).first()
    if not charter:
        seed_source_charter(db)
        charter = db.query(SourceCharter).filter(SourceCharter.code == source_code).first()

    now = datetime.datetime.now(datetime.timezone.utc)
    run = SourceRun(
        case_id=case.id,
        source_id=charter.id,
        operator_id=operator.id,
        query_input=query_input,
        status=status,
        error_detail=error_detail,
        started_at=now,
        completed_at=now,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


def make_accepted_record(
    db,
    case: Case,
    operator: User,
    source_code: str = "DOMAIN_RDAP",
    title: str = "Verified Domain Registration Snapshot",
    content: str = '{"ldhName": "acmetech.demo", "status": ["active"]}',
    source_url: str = "https://rdap.org/domain/acmetech.demo",
    triage_status: str = TriageStatus.ACCEPTED.value,
) -> Record:
    """Create an evidence record with deterministic SHA-256 hash."""
    run = make_source_run(db, case, operator, source_code=source_code, query_input=case.subject_identifier or "acmetech.demo")
    h = hashlib.sha256(content.encode("utf-8")).hexdigest().lower()
    now = datetime.datetime.now(datetime.timezone.utc)

    record = Record(
        case_id=case.id,
        source_run_id=run.id,
        source_id=run.source_id,
        title=title,
        source_url=source_url,
        raw_content=content,
        content_type="application/json" if content.startswith("{") else "text/plain",
        snapshot_hash=h,
        extractor_version="m2-v1.0",
        retrieved_at=now,
        triage_status=triage_status,
        triaged_by_id=operator.id if triage_status != TriageStatus.PENDING_TRIAGE.value else None,
        triaged_at=now if triage_status != TriageStatus.PENDING_TRIAGE.value else None,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
