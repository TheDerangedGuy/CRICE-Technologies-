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


class CaseStage(str, enum.Enum):
    INTAKE_DRAFT = "INTAKE_DRAFT"
    COMPLIANCE_GATE = "COMPLIANCE_GATE"
    COLLECT = "COLLECT"
    CLAIM_EXTRACTION = "CLAIM_EXTRACTION"
    CORRELATION_AND_SCORING = "CORRELATION_AND_SCORING"
    INDEPENDENT_REVIEW = "INDEPENDENT_REVIEW"
    BUILD_AND_QA = "BUILD_AND_QA"
    RELEASE_GATE = "RELEASE_GATE"
    CLOSED = "CLOSED"
    RECALLED = "RECALLED"


# Backward compatibility alias
StageEnum = CaseStage

# Canonical stage order for progression display
STAGE_ORDER = [
    CaseStage.INTAKE_DRAFT,
    CaseStage.COMPLIANCE_GATE,
    CaseStage.COLLECT,
    CaseStage.CLAIM_EXTRACTION,
    CaseStage.CORRELATION_AND_SCORING,
    CaseStage.INDEPENDENT_REVIEW,
    CaseStage.BUILD_AND_QA,
    CaseStage.RELEASE_GATE,
    CaseStage.CLOSED,
    CaseStage.RECALLED,
]


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
    Rows older than 90 seconds (2-3 TOTP windows) can be pruned.
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
            "stage IN ('INTAKE_DRAFT','COMPLIANCE_GATE','COLLECT','CLAIM_EXTRACTION',"
            "'CORRELATION_AND_SCORING','INDEPENDENT_REVIEW','BUILD_AND_QA',"
            "'RELEASE_GATE','CLOSED','RECALLED')",
            name="ck_cases_stage",
        ),
        sa.CheckConstraint(
            "reviewer_id IS NULL OR operator_id != reviewer_id",
            name="ck_cases_reviewer_not_operator",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    case_ref = sa.Column(sa.String(14), unique=True, nullable=False, index=True)
    client_name = sa.Column(sa.String(200), nullable=False)
    client_kyc_verified = sa.Column(sa.Boolean, default=False, nullable=False)
    msa_signed = sa.Column(sa.Boolean, default=False, nullable=False)
    purpose = sa.Column(sa.String(50), nullable=False)
    subject_type = sa.Column(sa.String(20), nullable=False)
    subject_name = sa.Column(sa.String(200), nullable=False)
    subject_identifier = sa.Column(sa.String(50), nullable=True)
    stage = sa.Column(sa.String(30), default=CaseStage.INTAKE_DRAFT.value, nullable=False)
    intake_approved = sa.Column(sa.Boolean, default=False, nullable=False)
    consent_verified = sa.Column(sa.Boolean, default=False, nullable=False)
    dossier_version = sa.Column(sa.Integer, default=1, nullable=False)
    is_recalled = sa.Column(sa.Boolean, default=False, nullable=False)
    rework_reason = sa.Column(sa.Text, nullable=True)

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
        return f"<Case {self.case_ref!r} stage={self.stage} v={self.dossier_version}>"


class AuditLog(Base):
    """Append-only audit log. No UPDATE or DELETE paths exist in application code.
    A Postgres trigger enforces this at the DB level in production."""

    __tablename__ = "audit_log"

    id = sa.Column(sa.Integer, primary_key=True)
    timestamp = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)
    user_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    case_id = sa.Column(sa.Integer, sa.ForeignKey("cases.id"), nullable=True)
    action = sa.Column(sa.String(100), nullable=False)
    from_stage = sa.Column(sa.String(30), nullable=True)
    to_stage = sa.Column(sa.String(30), nullable=True)
    allowed = sa.Column(sa.Boolean, default=True, nullable=False)
    detail = sa.Column(sa.JSON, nullable=True)
    ip = sa.Column(sa.String(45), nullable=True)

    user = relationship("User", foreign_keys=[user_id], lazy="select")
    case = relationship("Case", foreign_keys=[case_id], lazy="select")

    def __repr__(self):
        return f"<AuditLog id={self.id} action={self.action!r} allowed={self.allowed}>"
