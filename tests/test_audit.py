"""
tests/test_audit.py – Verification of append-only audit trail and compliance tracking.

Tests:
  - Every successful transition writes an audit entry with from_stage, to_stage, allowed=True.
  - Every denied transition writes an audit entry with allowed=False, from_stage, to_stage, and reason.
  - Audit log writer commits denied attempts even when service call raises HTTPException.
  - Case creation writes an initial audit record.
  - Database trigger blocks SQL UPDATE and DELETE operations on audit_log.
"""
from fastapi import HTTPException
import pytest
import sqlalchemy as sa

from app.audit.writer import log_action
from app.cases.service import advance_case, create_case
from app.models import AuditLog, CaseStage, PurposeEnum, SubjectType
from tests.conftest import make_accepted_record, make_case, make_user


def test_case_creation_logs_audit_entry(db):
    """Case creation must record an initial audit record with to_stage."""
    op = make_user(db, email="op_audit_create@crice.test")
    case = create_case(
        db=db,
        acting_user=op,
        client_name="Global Investment Banking Corp",
        purpose=PurposeEnum.corporate_due_diligence.value,
        subject_type=SubjectType.company.value,
        subject_name="Audit Target Corp",
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
    make_accepted_record(db, case, op)

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


def test_audit_log_immutability_blocks_update_and_delete(db):
    """Attempting SQL UPDATE or DELETE on audit_log must be blocked by DB trigger."""
    op = make_user(db, email="op_immutable@crice.test")
    entry = log_action(
        db,
        action="immutable_test_event",
        user_id=op.id,
        commit=True,
    )

    # 1. Attempt UPDATE
    with pytest.raises(Exception) as exc_up:
        db.execute(
            sa.text("UPDATE audit_log SET action = 'tampered' WHERE id = :id"),
            {"id": entry.id},
        )
        db.commit()
    db.rollback()
    assert "append-only" in str(exc_up.value).lower() or "forbidden" in str(exc_up.value).lower()

    # 2. Attempt DELETE
    with pytest.raises(Exception) as exc_del:
        db.execute(
            sa.text("DELETE FROM audit_log WHERE id = :id"),
            {"id": entry.id},
        )
        db.commit()
    db.rollback()
    assert "append-only" in str(exc_del.value).lower() or "forbidden" in str(exc_del.value).lower()

    # Verify record remained intact
    row = db.get(AuditLog, entry.id)
    assert row is not None
    assert row.action == "immutable_test_event"
