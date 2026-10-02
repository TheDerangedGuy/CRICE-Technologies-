"""
app/models.py – SQLAlchemy ORM models for M1.

All enums use native_enum=False (stored as VARCHAR) so the same models
work with both PostgreSQL (production) and SQLite (tests).

All datetime defaults are Python-side lambdas (not server_default) so
they work in SQLite too.
"""
import datetime
import enum

import sqlalchemy as sa
import sqlalchemy.orm as orm

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
STAGE_ORDER: list[StageEnum] = list(StageEnum)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ── ORM Models ────────────────────────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"

    id: orm.Mapped[int] = orm.mapped_column(sa.Integer, primary_key=True)
    email: orm.Mapped[str] = orm.mapped_column(
        sa.String(254), unique=True, nullable=False, index=True
    )
    full_name: orm.Mapped[str] = orm.mapped_column(sa.String(200), nullable=False)
    password_hash: orm.Mapped[str] = orm.mapped_column(sa.String(200), nullable=False)
    role: orm.Mapped[str] = orm.mapped_column(
        sa.Enum(UserRole, native_enum=False, length=30), nullable=False
    )
    totp_secret: orm.Mapped[str | None] = orm.mapped_column(
        sa.String(64), nullable=True
    )
    mfa_enabled: orm.Mapped[bool] = orm.mapped_column(
        sa.Boolean, default=False, nullable=False
    )
    is_active: orm.Mapped[bool] = orm.mapped_column(
        sa.Boolean, default=True, nullable=False
    )
    failed_logins: orm.Mapped[int] = orm.mapped_column(
        sa.Integer, default=0, nullable=False
    )
    locked_until: orm.Mapped[datetime.datetime | None] = orm.mapped_column(
        sa.DateTime(timezone=True), nullable=True
    )
    created_at: orm.Mapped[datetime.datetime] = orm.mapped_column(
        sa.DateTime(timezone=True), default=_now, nullable=False
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r} role={self.role}>"


class Case(Base):
    __tablename__ = "cases"

    id: orm.Mapped[int] = orm.mapped_column(sa.Integer, primary_key=True)
    case_ref: orm.Mapped[str] = orm.mapped_column(
        sa.String(20), unique=True, nullable=False, index=True
    )
    client_name: orm.Mapped[str] = orm.mapped_column(sa.String(200), nullable=False)
    purpose: orm.Mapped[str] = orm.mapped_column(
        sa.Enum(PurposeEnum, native_enum=False, length=50), nullable=False
    )
    subject_type: orm.Mapped[str] = orm.mapped_column(
        sa.Enum(SubjectType, native_enum=False, length=20), nullable=False
    )
    subject_name: orm.Mapped[str] = orm.mapped_column(sa.String(200), nullable=False)
    subject_identifier: orm.Mapped[str | None] = orm.mapped_column(
        sa.String(50), nullable=True
    )
    stage: orm.Mapped[str] = orm.mapped_column(
        sa.Enum(StageEnum, native_enum=False, length=20),
        default=StageEnum.INTAKE,
        nullable=False,
    )
    intake_approved: orm.Mapped[bool] = orm.mapped_column(
        sa.Boolean, default=False, nullable=False
    )
    operator_id: orm.Mapped[int] = orm.mapped_column(
        sa.Integer, sa.ForeignKey("users.id"), nullable=False
    )
    reviewer_id: orm.Mapped[int | None] = orm.mapped_column(
        sa.Integer, sa.ForeignKey("users.id"), nullable=True
    )
    created_by: orm.Mapped[int] = orm.mapped_column(
        sa.Integer, sa.ForeignKey("users.id"), nullable=False
    )
    created_at: orm.Mapped[datetime.datetime] = orm.mapped_column(
        sa.DateTime(timezone=True), default=_now, nullable=False
    )
    updated_at: orm.Mapped[datetime.datetime] = orm.mapped_column(
        sa.DateTime(timezone=True), default=_now, onupdate=_now, nullable=False
    )

    # Relationships
    operator: orm.Mapped["User"] = orm.relationship(
        "User", foreign_keys=[operator_id], lazy="select"
    )
    reviewer: orm.Mapped["User | None"] = orm.relationship(
        "User", foreign_keys=[reviewer_id], lazy="select"
    )
    creator: orm.Mapped["User"] = orm.relationship(
        "User", foreign_keys=[created_by], lazy="select"
    )

    def __repr__(self) -> str:
        return f"<Case {self.case_ref!r} stage={self.stage}>"


class AuditLog(Base):
    """Append-only audit log.  No UPDATE or DELETE paths exist anywhere in the codebase."""

    __tablename__ = "audit_log"

    id: orm.Mapped[int] = orm.mapped_column(sa.Integer, primary_key=True)
    timestamp: orm.Mapped[datetime.datetime] = orm.mapped_column(
        sa.DateTime(timezone=True), default=_now, nullable=False
    )
    user_id: orm.Mapped[int | None] = orm.mapped_column(
        sa.Integer, sa.ForeignKey("users.id"), nullable=True
    )
    case_id: orm.Mapped[int | None] = orm.mapped_column(
        sa.Integer, sa.ForeignKey("cases.id"), nullable=True
    )
    action: orm.Mapped[str] = orm.mapped_column(sa.String(100), nullable=False)
    detail: orm.Mapped[dict | None] = orm.mapped_column(sa.JSON, nullable=True)
    ip: orm.Mapped[str | None] = orm.mapped_column(sa.String(45), nullable=True)

    user: orm.Mapped["User | None"] = orm.relationship(
        "User", foreign_keys=[user_id], lazy="select"
    )
    case: orm.Mapped["Case | None"] = orm.relationship(
        "Case", foreign_keys=[case_id], lazy="select"
    )

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action!r}>"
