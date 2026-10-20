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


class SourceTier(str, enum.Enum):
    A = "A"
    B = "B"
    C = "C"


class SourceReliability(str, enum.Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"


class CollectionMode(str, enum.Enum):
    AUTOMATED = "AUTOMATED"
    MANUAL_CAPTURE = "MANUAL_CAPTURE"


class SourceRunStatus(str, enum.Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    FAILED = "FAILED"


class TriageStatus(str, enum.Enum):
    PENDING_TRIAGE = "PENDING_TRIAGE"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class MatchTier(str, enum.Enum):
    TIER_1 = "TIER_1"
    TIER_2 = "TIER_2"
    TIER_3 = "TIER_3"
    UNSCORED = "UNSCORED"


class AIRunStatus(str, enum.Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BYPASSED = "BYPASSED"


class ExtractionMethod(str, enum.Enum):
    AI_EXTRACTED = "AI_EXTRACTED"
    MANUAL = "MANUAL"


class ReviewStatus(str, enum.Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class DossierSection(str, enum.Enum):
    CONFIRMED_FINDING = "CONFIRMED_FINDING"
    UNRESOLVED_POSSIBLE_MATCH = "UNRESOLVED_POSSIBLE_MATCH"
    EXCLUDED = "EXCLUDED"


class AdverseCategory(str, enum.Enum):
    FRAUD = "FRAUD"
    CONVICTION = "CONVICTION"
    DEFAULT = "DEFAULT"
    SANCTIONS = "SANCTIONS"
    LITIGATION_ACCUSED = "LITIGATION_ACCUSED"
    REGULATORY_PENALTY = "REGULATORY_PENALTY"


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
    # Subject Disambiguation & Anchors
    subject_din = sa.Column(sa.String(20), nullable=True)
    subject_pan_or_gstin = sa.Column(sa.String(25), nullable=True)
    subject_dob_or_year = sa.Column(sa.String(20), nullable=True)
    subject_father_or_spouse = sa.Column(sa.String(120), nullable=True)
    subject_address = sa.Column(sa.String(500), nullable=True)
    subject_city = sa.Column(sa.String(100), nullable=True)
    ai_enabled = sa.Column(sa.Boolean, default=True, nullable=False)
    zero_findings_attested = sa.Column(sa.Boolean, default=False, nullable=False)

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
    source_runs = relationship("SourceRun", back_populates="case", lazy="select", order_by="SourceRun.started_at.desc()")
    records = relationship("Record", back_populates="case", lazy="select", order_by="Record.retrieved_at.desc()")
    ai_runs = relationship("AIRun", back_populates="case", lazy="select", order_by="AIRun.created_at.desc()")
    claims = relationship("Claim", back_populates="case", lazy="select", order_by="Claim.created_at.desc()")
    dossiers = relationship("Dossier", back_populates="case", lazy="select", order_by="Dossier.version.desc()")

    def __repr__(self):
        return f"<Case {self.case_ref!r} stage={self.stage} v={self.dossier_version}>"


class SourceCharter(Base):
    __tablename__ = "source_charter"
    __table_args__ = (
        sa.CheckConstraint("tier IN ('A','B','C')", name="ck_source_charter_tier"),
        sa.CheckConstraint(
            "default_reliability IN ('A','B','C','D','E','F')",
            name="ck_source_charter_reliability",
        ),
        sa.CheckConstraint(
            "collection_mode IN ('AUTOMATED','MANUAL_CAPTURE')",
            name="ck_source_charter_mode",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    code = sa.Column(sa.String(50), unique=True, nullable=False, index=True)
    name = sa.Column(sa.String(120), nullable=False)
    owner = sa.Column(sa.String(120), nullable=False)
    tier = sa.Column(sa.String(1), nullable=False)
    default_reliability = sa.Column(sa.String(1), nullable=False)
    collection_mode = sa.Column(sa.String(20), nullable=False)
    legal_basis = sa.Column(sa.String(255), nullable=False)
    is_active = sa.Column(sa.Boolean, default=True, nullable=False)
    created_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)

    def __repr__(self):
        return f"<SourceCharter {self.code} tier={self.tier} mode={self.collection_mode}>"


class SourceRun(Base):
    __tablename__ = "source_runs"
    __table_args__ = (
        sa.CheckConstraint(
            "status IN ('FOUND','NOT_FOUND','FAILED')",
            name="ck_source_runs_status",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    case_id = sa.Column(sa.Integer, sa.ForeignKey("cases.id"), nullable=False, index=True)
    source_id = sa.Column(sa.Integer, sa.ForeignKey("source_charter.id"), nullable=False)
    operator_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=False)
    query_input = sa.Column(sa.String(255), nullable=False)
    status = sa.Column(sa.String(20), nullable=False)
    error_detail = sa.Column(sa.Text, nullable=True)
    started_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)
    completed_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)

    case = relationship("Case", back_populates="source_runs", lazy="select")
    source = relationship("SourceCharter", foreign_keys=[source_id], lazy="select")
    operator = relationship("User", foreign_keys=[operator_id], lazy="select")
    records = relationship("Record", back_populates="source_run", lazy="select")

    def __repr__(self):
        return f"<SourceRun id={self.id} case_id={self.case_id} status={self.status}>"


class Record(Base):
    """
    Immutable Evidence Snapshots.
    Once inserted, raw_content, snapshot_hash, source_url, and retrieved_at
    must never be modified or deleted. Only triage decisions can be updated.
    """
    __tablename__ = "records"
    __table_args__ = (
        sa.CheckConstraint(
            "triage_status IN ('PENDING_TRIAGE','ACCEPTED','REJECTED')",
            name="ck_records_triage_status",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    case_id = sa.Column(sa.Integer, sa.ForeignKey("cases.id"), nullable=False, index=True)
    source_run_id = sa.Column(sa.Integer, sa.ForeignKey("source_runs.id"), nullable=False)
    source_id = sa.Column(sa.Integer, sa.ForeignKey("source_charter.id"), nullable=False)
    title = sa.Column(sa.String(255), nullable=False)
    source_url = sa.Column(sa.String(500), nullable=False)
    raw_content = sa.Column(sa.Text, nullable=False)
    content_type = sa.Column(sa.String(50), default="application/json", nullable=False)
    snapshot_hash = sa.Column(sa.String(64), nullable=False)
    extractor_version = sa.Column(sa.String(30), default="m2-v1.0", nullable=False)
    retrieved_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)
    triage_status = sa.Column(sa.String(20), default=TriageStatus.PENDING_TRIAGE.value, nullable=False)
    triage_note = sa.Column(sa.Text, nullable=True)
    triaged_by_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    triaged_at = sa.Column(sa.DateTime(timezone=True), nullable=True)

    case = relationship("Case", back_populates="records", lazy="select")
    source_run = relationship("SourceRun", back_populates="records", lazy="select")
    source = relationship("SourceCharter", foreign_keys=[source_id], lazy="select")
    triaged_by = relationship("User", foreign_keys=[triaged_by_id], lazy="select")
    claims = relationship("Claim", foreign_keys="Claim.primary_record_id", back_populates="primary_record", lazy="select")

    def __repr__(self):
        return f"<Record id={self.id} title={self.title!r} hash={self.snapshot_hash[:8]} triage={self.triage_status}>"


class AIRun(Base):
    __tablename__ = "ai_runs"
    __table_args__ = (
        sa.CheckConstraint(
            "status IN ('SUCCEEDED', 'FAILED', 'BYPASSED')",
            name="ck_ai_runs_status",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    case_id = sa.Column(sa.Integer, sa.ForeignKey("cases.id"), nullable=False, index=True)
    operator_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=False)
    model_name = sa.Column(sa.String(80), nullable=False)
    prompt_version = sa.Column(sa.String(40), default="m4-v1.0", nullable=False)
    input_record_ids_json = sa.Column(sa.Text, nullable=False)
    raw_prompt = sa.Column(sa.Text, nullable=False)
    raw_output = sa.Column(sa.Text, nullable=False)
    claims_extracted_count = sa.Column(sa.Integer, default=0, nullable=False)
    claims_rejected_citation_count = sa.Column(sa.Integer, default=0, nullable=False)
    status = sa.Column(sa.String(20), nullable=False)
    error_detail = sa.Column(sa.Text, nullable=True)
    created_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)

    case = relationship("Case", back_populates="ai_runs", lazy="select")
    operator = relationship("User", foreign_keys=[operator_id], lazy="select")
    claims = relationship("Claim", back_populates="ai_run", lazy="select")

    def __repr__(self):
        return f"<AIRun id={self.id} case_id={self.case_id} model={self.model_name!r} status={self.status}>"


class Claim(Base):
    __tablename__ = "claims"
    __table_args__ = (
        sa.CheckConstraint(
            "extraction_method IN ('AI_EXTRACTED', 'MANUAL')",
            name="ck_claims_extraction_method",
        ),
        sa.CheckConstraint(
            "match_tier IN ('TIER_1', 'TIER_2', 'TIER_3', 'UNSCORED')",
            name="ck_claims_match_tier",
        ),
        sa.CheckConstraint(
            "source_reliability IN ('A', 'B', 'C', 'D', 'E', 'F')",
            name="ck_claims_source_reliability",
        ),
        sa.CheckConstraint(
            "identity_confidence BETWEEN 1 AND 6",
            name="ck_claims_identity_confidence",
        ),
        sa.CheckConstraint(
            "adverse_category IS NULL OR adverse_category IN ('FRAUD', 'CONVICTION', 'DEFAULT', 'SANCTIONS', 'LITIGATION_ACCUSED', 'REGULATORY_PENALTY')",
            name="ck_claims_adverse_category",
        ),
        sa.CheckConstraint(
            "review_status IN ('PENDING_REVIEW', 'APPROVED', 'REJECTED')",
            name="ck_claims_review_status",
        ),
        sa.CheckConstraint(
            "dossier_section IN ('CONFIRMED_FINDING', 'UNRESOLVED_POSSIBLE_MATCH', 'EXCLUDED')",
            name="ck_claims_dossier_section",
        ),
    )

    id = sa.Column(sa.Integer, primary_key=True)
    case_id = sa.Column(sa.Integer, sa.ForeignKey("cases.id"), nullable=False, index=True)
    ai_run_id = sa.Column(sa.Integer, sa.ForeignKey("ai_runs.id"), nullable=True)
    created_by_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=False)
    extraction_method = sa.Column(sa.String(20), default=ExtractionMethod.AI_EXTRACTED.value, nullable=False)

    # Atomic Claim Triple & Provenance
    subject_entity = sa.Column(sa.String(255), nullable=False)
    predicate = sa.Column(sa.String(120), nullable=False)
    object_value = sa.Column(sa.Text, nullable=False)
    verbatim_quote = sa.Column(sa.Text, nullable=True)
    quote_verified = sa.Column(sa.Boolean, default=False, nullable=False)
    primary_record_id = sa.Column(sa.Integer, sa.ForeignKey("records.id"), nullable=False)
    supporting_record_ids_json = sa.Column(sa.Text, default="[]", nullable=False)
    snapshot_hash = sa.Column(sa.String(64), nullable=False)
    extractor_version = sa.Column(sa.String(30), default="m4-v1.0", nullable=False)

    # Entity Resolution & Two-Axis Scoring
    extracted_identifiers_json = sa.Column(sa.Text, default="{}", nullable=False)
    matched_attributes_json = sa.Column(sa.Text, default="[]", nullable=False)
    match_tier = sa.Column(sa.String(10), default=MatchTier.UNSCORED.value, nullable=False)
    source_reliability = sa.Column(sa.String(1), nullable=False)
    reliability_downgrade_reason = sa.Column(sa.Text, nullable=True)
    identity_confidence = sa.Column(sa.Integer, default=6, nullable=False)
    scoring_rationale = sa.Column(sa.Text, nullable=True)

    # Adverse-Claim & Corroboration
    is_adverse = sa.Column(sa.Boolean, default=False, nullable=False)
    adverse_category = sa.Column(sa.String(50), nullable=True)
    finding_group_key = sa.Column(sa.String(64), nullable=True)
    origin_domain = sa.Column(sa.String(120), nullable=True)

    # Independent Reviewer Gate
    review_status = sa.Column(sa.String(20), default=ReviewStatus.PENDING_REVIEW.value, nullable=False)
    reviewed_by_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    review_note = sa.Column(sa.Text, nullable=True)
    reviewed_at = sa.Column(sa.DateTime(timezone=True), nullable=True)
    dossier_section = sa.Column(sa.String(35), default=DossierSection.EXCLUDED.value, nullable=False)

    created_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)
    updated_at = sa.Column(sa.DateTime(timezone=True), default=_now, onupdate=_now, nullable=False)

    case = relationship("Case", back_populates="claims", lazy="select")
    ai_run = relationship("AIRun", back_populates="claims", lazy="select")
    created_by = relationship("User", foreign_keys=[created_by_id], lazy="select")
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id], lazy="select")
    primary_record = relationship("Record", foreign_keys=[primary_record_id], back_populates="claims", lazy="select")

    def __repr__(self):
        return f"<Claim id={self.id} case_id={self.case_id} [{self.source_reliability}{self.identity_confidence}] {self.predicate}={self.object_value[:30]!r}>"


class Dossier(Base):
    __tablename__ = "dossiers"

    id = sa.Column(sa.Integer, primary_key=True)
    case_id = sa.Column(sa.Integer, sa.ForeignKey("cases.id"), nullable=False, index=True)
    version = sa.Column(sa.Integer, nullable=False)
    compiled_by_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=False)
    html_content = sa.Column(sa.Text, nullable=False)
    pdf_bytes_b64 = sa.Column(sa.Text, nullable=True)
    dossier_hash = sa.Column(sa.String(64), nullable=False)
    coverage_manifest_json = sa.Column(sa.Text, nullable=False)
    confirmed_findings_count = sa.Column(sa.Integer, default=0, nullable=False)
    unresolved_matches_count = sa.Column(sa.Integer, default=0, nullable=False)
    delivery_token = sa.Column(sa.String(64), unique=True, nullable=True, index=True)
    delivery_expires_at = sa.Column(sa.DateTime(timezone=True), nullable=True)
    is_revoked = sa.Column(sa.Boolean, default=False, nullable=False)
    released_by_id = sa.Column(sa.Integer, sa.ForeignKey("users.id"), nullable=True)
    released_at = sa.Column(sa.DateTime(timezone=True), nullable=True)
    created_at = sa.Column(sa.DateTime(timezone=True), default=_now, nullable=False)

    case = relationship("Case", back_populates="dossiers", lazy="select")
    compiled_by = relationship("User", foreign_keys=[compiled_by_id], lazy="select")
    released_by = relationship("User", foreign_keys=[released_by_id], lazy="select")

    def __repr__(self):
        return f"<Dossier id={self.id} case_id={self.case_id} v={self.version} hash={self.dossier_hash[:8]}>"




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

