"""
tests/test_audit.py – Verification of append-only audit trail and compliance tracking.

Tests:
  - Every successful transition writes an audit entry with from_stage, to_stage, allowed=True.
  - Every denied transition writes an audit entry with allowed=False, from_stage, to_stage, and reason.
  - Audit log writer commits denied attempts even when service call raises HTTPException.
  - Case creation writes an initial audit record.
"""
from fastapi import HTTPException
import pytest

from app.audit.writer import log_action
from app.cases.service import advance_case, create_case
from app.models import AuditLog, Case, CaseStage, PurposeEnum, SubjectType, UserRole
from tests.conftest import make_case, make_user


def test_case_creation_logs_audit_entry(db):
    """Case creation must record an initial audit record with to_stage."""
    op = make_user(db, email="op_audit_create@crice.test")
    case = create_case(
        db=db,
        acting_user=op,
        client_name="Audit Client",
        purpose=PurposeEnum.corporate_due_diligence.value,
        subject_type=SubjectType.company.value,
        subject_name="Audit Target Corp",
        client_kyc_verified=True,
        msa_signed=True,
    )
    entry = (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case.id, AuditLog.action == "case_created")
        .first()
    )
    assert entry is not None
    assert entry.user_id == op.id
    assert entry.to_stage == CaseStage.COLLECT.value
    assert entry.allowed is True


def test_successful_transition_records_stages_and_allowed_true(db):
    """Successful stage transition writes from_stage, to_stage, and allowed=True."""
    op = make_user(db, email="op_audit_succ@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    advance_case(case, op, CaseStage.CLAIM_EXTRACTION.value, db)

    entry = (
        db.query(AuditLog)
        .filter(
            AuditLog.case_id == case.id,
            AuditLog.from_stage == CaseStage.COLLECT.value,
            AuditLog.to_stage == CaseStage.CLAIM_EXTRACTION.value,
        )
        .first()
    )
    assert entry is not None
    assert entry.action == "advance_stage"
    assert entry.allowed is True
    assert entry.user_id == op.id


def test_denied_transition_records_stages_and_allowed_false(db):
    """Denied transition commits an audit entry with allowed=False and detailed reason."""
    op = make_user(db, email="op_audit_fail@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    # Attempt stage skipping: COLLECT -> BUILD_AND_QA
    with pytest.raises(HTTPException) as exc_info:
        advance_case(case, op, CaseStage.BUILD_AND_QA.value, db)
    assert exc_info.value.status_code == 400

    entry = (
        db.query(AuditLog)
        .filter(
            AuditLog.case_id == case.id,
            AuditLog.action == "transition_denied",
        )
        .first()
    )
    assert entry is not None
    assert entry.allowed is False
    assert entry.from_stage == CaseStage.COLLECT.value
    assert entry.to_stage == CaseStage.BUILD_AND_QA.value
    assert "Stage skipping is prohibited" in entry.detail.get("reason", "")
