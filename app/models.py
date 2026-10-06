"""
app/models.py – SQLAlchemy ORM models for M1.

Uses the classic Column() API for Python 3.14 / SQLAlchemy 2.0 compatibility.
Enums use native_enum=False (VARCHAR) for SQLite/PostgreSQL portability.
Datetimes are timezone-aware UTC (Python-side default=_now, not server_default).
"""
import datetime
import enum

import sqlalchemy as sa
from sqlalchemy.orm import relationship

from app.db import Base


# ── Enums ────────────────────────────────────────────────────────────────────


class UserRole(str, enum.Enum):
    operator = "operator"
    reviewer = "reviewer"
    compliance_admin = "compliance_admin"


class PurposeEnum(str, enum.Enum):
    corporate_due_diligence = "corporate_due_diligence"
    litigation_support = "litigation_support"
    vendor_verification = "vendor_verification"
    employee_screening_with_consent = "employee_screening_with_consent"
    fraud_investigation = "fraud_investigation"


class SubjectType(str, enum.Enum):
    company = "company"
    person = "person"


class StageEnum(str, enum.Enum):
    INTAKE = "INTAKE"
    COLLECT = "COLLECT"
    PRE_AI_REVIEW = "PRE_AI_REVIEW"
    AI_PROCESSING = "AI_PROCESSING"
    POST_AI_REVIEW = "POST_AI_REVIEW"
    BUILD = "BUILD"
    RELEASE = "RELEASE"
    CLOSED = "CLOSED"


# Ordered list used by advance_case() to validate one-step forward movement.
STAGE_ORDER = list(StageEnum)


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


# ── ORM Models ────────────────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        sa.CheckConstraint(
            "role IN ('operator','reviewer','compliance_admin')",
            name="ck_users_role",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    email = sa.Column(sa.String(254), unique=True, nullable=False, index=True)
    full_name = sa.Column(sa.String(200), nullable=False)
    password_hash = sa.Column(sa.String(200), nullable=False)
    role = sa.Column(sa.String(30), nullable=False)
    # totp_secret stored Fernet-encrypted; NULL until first MFA setup attempt.
    totp_secret_enc = sa.Column(sa.Text, nullable=True)
    mfa_enabled = sa.Column(sa.Boolean, default=False, nullable=False)
    is_active = sa.Column(sa.Boolean, default=True, nullable=False)
    failed_logins = sa.Column(sa.Integer, default=0, nullable=False)
    locked_until = sa.Column(sa.DateTime(timezone=True), nullable=True)
    created_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)

    def __repr__(self):
        return f"<User id={self.id} email={self.email!r} role={self.role}>"


class Session(Base):
    """
    Server-side session record.

    A signed session_id (opaque token) is stored in the HttpOnly cookie.
    The corresponding row here holds the user, MFA status, CSRF token,
    idle/absolute expiry, and a revoked flag for explicit logout/deactivation.
    """
    __tablename__ = "sessions"

    id = sa.Column(sa.Integer, primary_key=True)
    session_id = sa.Column(sa.String(64), unique=True, nullable=False, index=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=False)
    mfa_verified = sa.Column(sa.Boolean, default=False, nullable=False)
    csrf_token = sa.Column(sa.String(64), nullable=False)
    # Idle timeout: updated on every authenticated request.
    last_active_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)
    # Absolute timeout: never updated after creation.
    created_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)
    revoked = sa.Column(sa.Boolean, default=False, nullable=False)

    user = relationship("User", foreign_keys=[user_id], lazy="select")

    def __repr__(self):
        return f"<Session id={self.session_id[:8]}… user={self.user_id} mfa={self.mfa_verified}>"


class TotpUsed(Base):
    """
    Records TOTP codes that have been consumed to prevent replay attacks.
    Rows older than 90 seconds (2 TOTP windows) can be pruned.
    """
    __tablename__ = "totp_used"

    id = sa.Column(sa.Integer, primary_key=True)
    user_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=False)
    code = sa.Column(sa.String(6), nullable=False)
    used_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)

    __table_args__ = (
        sa.UniqueConstraint("user_id", "code", name="uq_totp_used_user_code"),
    )


class Case(Base):
    __tablename__ = "cases"
    __table_args__ = (
        sa.CheckConstraint(
            "subject_type IN ('company','person')",
            name="ck_cases_subject_type",
        ),
        sa.CheckConstraint(
            "stage IN ('INTAKE','COLLECT','PRE_AI_REVIEW','AI_PROCESSING',"
            "'POST_AI_REVIEW','BUILD','RELEASE','CLOSED')",
            name="ck_cases_stage",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    case_ref = sa.Column(sa.String(20), unique=True, nullable=False, index=True)
    client_name = sa.Column(sa.String(200), nullable=False)
    purpose = sa.Column(sa.String(50), nullable=False)
    subject_type = sa.Column(sa.String(20), nullable=False)
    subject_name = sa.Column(sa.String(200), nullable=False)
    subject_identifier = sa.Column(sa.String(50), nullable=True)
    stage = sa.Column(sa.String(20), default=StageEnum.INTAKE.value, nullable=False)
    intake_approved = sa.Column(sa.Boolean, default=False, nullable=False)
    operator_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=False)
    reviewer_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    created_by = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=False)
    created_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)
    updated_at = sa.Column(
        sa.DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    operator = relationship("User", foreign_keys=[operator_id], lazy="select")
    reviewer = relationship("User", foreign_keys=[reviewer_id], lazy="select")
    creator = relationship("User", foreign_keys=[created_by], lazy="select")

    def __repr__(self):
        return f"<Case {self.case_ref!r} stage={self.stage}>"


class AuditLog(Base):
    """Append-only audit log. No UPDATE or DELETE paths exist in application code.
    A Postgres trigger enforces this at the DB level in production."""

    __tablename__ = "audit_log"

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)
    user_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    case_id = sa.Column(sa.Integer, sa.ForeignKey("cases.id"), nullable=True)
    action = sa.Column(sa.String(100), nullable=False)
    detail = sa.Column(sa.JSON, nullable=True)
    ip = sa.Column(sa.String(45), nullable=True)

    user = relationship("User", foreign_keys=[user_id], lazy="select")
    case = relationship("Case", foreign_keys=[case_id], lazy="select")

    def __repr__(self):
        return f"<AuditLog id={self.id} action={self.action!r}>"
