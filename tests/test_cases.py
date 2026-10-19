"""
tests/test_cases.py – Acceptance and state-machine test suite for the CRICE Case DAG.

Covers:
  - Unique case_ref format matching ^CRICE-[0-9A-F]{8}$
  - Auto-advance on company intake with KYC/MSA
  - Compliance Gate human review for person subjects & fraud investigations
  - Consent verification gate for employee screening
  - Strict stage skipping prevention (returns 400, logged as allowed=False)
  - Bilateral separation of duties (operator != reviewer) in service and DB constraint
  - Entering and completing Independent Review role restrictions
  - Reviewer rework loops with mandatory >= 10 char justification
  - Compliance Admin only release & close
  - Post-release recall mechanics (version increment + is_recalled flag)
"""
import re
import pytest
from sqlalchemy.exc import IntegrityError

from app.cases.service import (
    advance_case,
    approve_intake,
    assign_reviewer,
    create_case,
    recall_case,
    rework_case,
    verify_consent,
)
from app.models import (
    AuditLog,
    Case,
    CaseStage,
    PurposeEnum,
    SubjectType,
    User,
    UserRole,
)
from tests.conftest import csrf_token_for, make_case, make_session, make_user


# ── Case Ref Format & Uniqueness ──────────────────────────────────────────────


def test_case_ref_format_and_uniqueness(db):
    """Case ref must match ^CRICE-[0-9A-F]{8}$ and be unique."""
    op = make_user(db, email="op_ref@crice.test")
    c1 = create_case(
        db=db,
        acting_user=op,
        client_name="Client A",
        purpose=PurposeEnum.corporate_due_diligence.value,
        subject_type=SubjectType.company.value,
        subject_name="Alpha Corp",
        client_kyc_verified=True,
        msa_signed=True,
    )
    c2 = create_case(
        db=db,
        acting_user=op,
        client_name="Client B",
        purpose=PurposeEnum.corporate_due_diligence.value,
        subject_type=SubjectType.company.value,
        subject_name="Beta Corp",
        client_kyc_verified=True,
        msa_signed=True,
    )
    pattern = re.compile(r"^CRICE-[0-9A-F]{8}$")
    assert pattern.match(c1.case_ref), f"Ref {c1.case_ref} does not match format"
    assert pattern.match(c2.case_ref), f"Ref {c2.case_ref} does not match format"
    assert c1.case_ref != c2.case_ref


# ── Auto-Advance vs Compliance Gate ───────────────────────────────────────────


def test_company_intake_auto_advances_with_kyc_and_msa(db):
    """Company subject with standard purpose + verified KYC & MSA auto-advances to COLLECT."""
    op = make_user(db, email="op_auto@crice.test")
    case = create_case(
        db=db,
        acting_user=op,
        client_name="Verified Partner Ltd",
        purpose=PurposeEnum.corporate_due_diligence.value,
        subject_type=SubjectType.company.value,
        subject_name="Target Ltd",
        client_kyc_verified=True,
        msa_signed=True,
    )
    assert case.stage == CaseStage.COLLECT.value
    assert case.intake_approved is True


def test_company_intake_without_kyc_halts_at_compliance_gate(db):
    """Company subject without verified KYC/MSA halts at COMPLIANCE_GATE."""
    op = make_user(db, email="op_nokyc@crice.test")
    case = create_case(
        db=db,
        acting_user=op,
        client_name="Unverified Client",
        purpose=PurposeEnum.corporate_due_diligence.value,
        subject_type=SubjectType.company.value,
        subject_name="Target Ltd",
        client_kyc_verified=False,
        msa_signed=False,
    )
    assert case.stage == CaseStage.COMPLIANCE_GATE.value
    assert case.intake_approved is False


def test_person_intake_halts_at_compliance_gate(db):
    """Person subject always halts at COMPLIANCE_GATE."""
    op = make_user(db, email="op_person@crice.test")
    case = create_case(
        db=db,
        acting_user=op,
        client_name="Client Corp",
        purpose=PurposeEnum.corporate_due_diligence.value,
        subject_type=SubjectType.person.value,
        subject_name="Jane Doe",
        client_kyc_verified=True,
        msa_signed=True,
    )
    assert case.stage == CaseStage.COMPLIANCE_GATE.value
    assert case.intake_approved is False


def test_operator_cannot_advance_compliance_gate(client, db):
    """Operator cannot advance a case in COMPLIANCE_GATE."""
    op = make_user(db, email="op_gate@crice.test", role=UserRole.operator)
    case = make_case(
        db,
        operator=op,
        subject_type=SubjectType.person,
        stage=CaseStage.COMPLIANCE_GATE,
        intake_approved=False,
    )
    _row, cookies = make_session(db, op)

    r = client.post(
        f"/cases/{case.id}/advance",
        data={"to_stage": CaseStage.COLLECT.value, "_csrf": csrf_token_for(_row)},
        cookies=cookies,
        follow_redirects=False,
    )
    assert r.status_code == 403

    # Verify audit denial was committed
    denial = (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case.id, AuditLog.allowed.is_(False))
        .first()
    )
    assert denial is not None
    assert denial.from_stage == CaseStage.COMPLIANCE_GATE.value
    assert denial.to_stage == CaseStage.COLLECT.value


def test_compliance_admin_can_approve_intake(client, db):
    """Compliance Admin can approve intake at COMPLIANCE_GATE."""
    op = make_user(db, email="op_intake@crice.test", role=UserRole.operator)
    admin = make_user(db, email="admin_intake@crice.test", role=UserRole.compliance_admin)
    case = make_case(
        db,
        operator=op,
        subject_type=SubjectType.person,
        stage=CaseStage.COMPLIANCE_GATE,
        intake_approved=False,
    )
    _row, cookies = make_session(db, admin)

    r = client.post(
        f"/cases/{case.id}/approve_intake",
        data={"_csrf": csrf_token_for(_row)},
        cookies=cookies,
        follow_redirects=False,
    )
    assert r.status_code == 302
    db.refresh(case)
    assert case.stage == CaseStage.COLLECT.value
    assert case.intake_approved is True


# ── Consent Gate ──────────────────────────────────────────────────────────────


def test_employee_screening_requires_verified_consent(client, db):
    """Employee screening purpose halts until consent is verified."""
    op = make_user(db, email="op_screen@crice.test", role=UserRole.operator)
    admin = make_user(db, email="admin_screen@crice.test", role=UserRole.compliance_admin)
    case = make_case(
        db,
        operator=op,
        subject_type=SubjectType.person,
        purpose=PurposeEnum.employee_screening_with_consent,
        stage=CaseStage.COMPLIANCE_GATE,
        consent_verified=False,
    )
    _row, cookies = make_session(db, admin)

    # 1. Admin tries to approve intake without consent -> rejected
    r = client.post(
        f"/cases/{case.id}/approve_intake",
        data={"_csrf": csrf_token_for(_row)},
        cookies=cookies,
        follow_redirects=False,
    )
    assert r.status_code == 403

    # 2. Verify consent token
    r_consent = client.post(
        f"/cases/{case.id}/verify_consent",
        data={"_csrf": csrf_token_for(_row)},
        cookies=cookies,
        follow_redirects=False,
    )
    assert r_consent.status_code == 302
    db.refresh(case)
    assert case.consent_verified is True

    # 3. Now approve intake -> succeeds
    r_approve = client.post(
        f"/cases/{case.id}/approve_intake",
        data={"_csrf": csrf_token_for(_row)},
        cookies=cookies,
        follow_redirects=False,
    )
    assert r_approve.status_code == 302
    db.refresh(case)
    assert case.stage == CaseStage.COLLECT.value


# ── Stage Skipping Prohibition ────────────────────────────────────────────────


def test_stage_skipping_prohibited(client, db):
    """Skipping stages forward (e.g. COLLECT -> BUILD_AND_QA) is blocked with 400 and logged."""
    op = make_user(db, email="op_skip@crice.test", role=UserRole.operator)
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)
    _row, cookies = make_session(db, op)

    r = client.post(
        f"/cases/{case.id}/advance",
        data={"to_stage": CaseStage.BUILD_AND_QA.value, "_csrf": csrf_token_for(_row)},
        cookies=cookies,
        follow_redirects=False,
    )
    assert r.status_code == 400

    denial = (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case.id, AuditLog.allowed.is_(False))
        .first()
    )
    assert denial is not None
    assert denial.from_stage == CaseStage.COLLECT.value
    assert denial.to_stage == CaseStage.BUILD_AND_QA.value


# ── Bilateral Separation of Duties ────────────────────────────────────────────


def test_bilateral_separation_service_layer(db):
    """Operator cannot be assigned as reviewer via service layer."""
    op = make_user(db, email="op_dual@crice.test", role=UserRole.operator)
    admin = make_user(db, email="admin_dual@crice.test", role=UserRole.compliance_admin)
    case = make_case(db, operator=op, stage=CaseStage.COLLECT)

    with pytest.raises(Exception) as exc_info:
        assign_reviewer(case, admin, op.id, db)
    assert "Bilateral" in str(exc_info.value) or "conflict" in str(exc_info.value).lower()


def test_bilateral_separation_db_constraint(db):
    """Database check constraint blocks operator_id == reviewer_id."""
    op = make_user(db, email="op_db@crice.test", role=UserRole.operator)
    case = make_case(db, operator=op, stage=CaseStage.COLLECT)

    case.reviewer_id = op.id
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()


# ── Independent Review & Rework Loops ─────────────────────────────────────────


def test_entering_independent_review_requires_reviewer(client, db):
    """Cannot advance to INDEPENDENT_REVIEW without assigned reviewer."""
    op = make_user(db, email="op_rev@crice.test", role=UserRole.operator)
    case = make_case(
        db,
        operator=op,
        stage=CaseStage.CORRELATION_AND_SCORING,
        reviewer=None,
    )
    _row, cookies = make_session(db, op)

    r = client.post(
        f"/cases/{case.id}/advance",
        data={"to_stage": CaseStage.INDEPENDENT_REVIEW.value, "_csrf": csrf_token_for(_row)},
        cookies=cookies,
        follow_redirects=False,
    )
    assert r.status_code == 403


def test_only_assigned_reviewer_can_complete_independent_review(client, db):
    """Only the assigned reviewer can advance from INDEPENDENT_REVIEW to BUILD_AND_QA."""
    op = make_user(db, email="op_ir@crice.test", role=UserRole.operator)
    rev = make_user(db, email="rev_ir@crice.test", role=UserRole.reviewer)
    admin = make_user(db, email="admin_ir@crice.test", role=UserRole.compliance_admin)

    case = make_case(
        db,
        operator=op,
        stage=CaseStage.INDEPENDENT_REVIEW,
        reviewer=rev,
    )

    # 1. Operator attempts advance -> blocked (403)
    _row_op, cookies_op = make_session(db, op)
    r_op = client.post(
        f"/cases/{case.id}/advance",
        data={"to_stage": CaseStage.BUILD_AND_QA.value, "_csrf": csrf_token_for(_row_op)},
        cookies=cookies_op,
        follow_redirects=False,
    )
    assert r_op.status_code == 403

    # 2. Compliance Admin attempts advance -> blocked (403)
    _row_admin, cookies_admin = make_session(db, admin)
    r_admin = client.post(
        f"/cases/{case.id}/advance",
        data={"to_stage": CaseStage.BUILD_AND_QA.value, "_csrf": csrf_token_for(_row_admin)},
        cookies=cookies_admin,
        follow_redirects=False,
    )
    assert r_admin.status_code == 403

    # 3. Assigned Reviewer attempts advance -> succeeds
    _row_rev, cookies_rev = make_session(db, rev)
    r_rev = client.post(
        f"/cases/{case.id}/advance",
        data={"to_stage": CaseStage.BUILD_AND_QA.value, "_csrf": csrf_token_for(_row_rev)},
        cookies=cookies_rev,
        follow_redirects=False,
    )
    assert r_rev.status_code == 302
    db.refresh(case)
    assert case.stage == CaseStage.BUILD_AND_QA.value


def test_reviewer_rework_loop_with_mandatory_reason(client, db):
    """Reviewer can return case for rework to COLLECT with mandatory reason."""
    op = make_user(db, email="op_rw@crice.test", role=UserRole.operator)
    rev = make_user(db, email="rev_rw@crice.test", role=UserRole.reviewer)

    case = make_case(
        db,
        operator=op,
        stage=CaseStage.INDEPENDENT_REVIEW,
        reviewer=rev,
    )
    _row, cookies = make_session(db, rev)

    # 1. Rework with insufficient reason (< 10 chars) -> 400
    r_bad = client.post(
        f"/cases/{case.id}/rework",
        data={
            "to_stage": CaseStage.COLLECT.value,
            "rework_reason": "Too short",
            "_csrf": csrf_token_for(_row),
        },
        cookies=cookies,
        follow_redirects=False,
    )
    assert r_bad.status_code == 400

    # 2. Rework with valid reason >= 10 chars -> succeeds
    reason = "Corporate registry evidence lacks director appointment filings."
    r_good = client.post(
        f"/cases/{case.id}/rework",
        data={
            "to_stage": CaseStage.COLLECT.value,
            "rework_reason": reason,
            "_csrf": csrf_token_for(_row),
        },
        cookies=cookies,
        follow_redirects=False,
    )
    assert r_good.status_code == 302
    db.refresh(case)
    assert case.stage == CaseStage.COLLECT.value
    assert case.rework_reason == reason


# ── Release & Post-Release Recall ─────────────────────────────────────────────


def test_operator_cannot_close_case(client, db):
    """Operator cannot close a case from RELEASE_GATE."""
    op = make_user(db, email="op_close@crice.test", role=UserRole.operator)
    case = make_case(db, operator=op, stage=CaseStage.RELEASE_GATE)
    _row, cookies = make_session(db, op)

    r = client.post(
        f"/cases/{case.id}/advance",
        data={"to_stage": CaseStage.CLOSED.value, "_csrf": csrf_token_for(_row)},
        cookies=cookies,
        follow_redirects=False,
    )
    assert r.status_code == 403


def test_compliance_admin_can_close_case(client, db):
    """Compliance Admin can advance RELEASE_GATE -> CLOSED."""
    op = make_user(db, email="op_admcl@crice.test", role=UserRole.operator)
    admin = make_user(db, email="admin_cl@crice.test", role=UserRole.compliance_admin)
    case = make_case(db, operator=op, stage=CaseStage.RELEASE_GATE)
    _row, cookies = make_session(db, admin)

    r = client.post(
        f"/cases/{case.id}/advance",
        data={"to_stage": CaseStage.CLOSED.value, "_csrf": csrf_token_for(_row)},
        cookies=cookies,
        follow_redirects=False,
    )
    assert r.status_code == 302
    db.refresh(case)
    assert case.stage == CaseStage.CLOSED.value


def test_compliance_admin_recall_mechanism(client, db):
    """Compliance Admin can recall a CLOSED case, setting is_recalled=True & incrementing version."""
    op = make_user(db, email="op_rec@crice.test", role=UserRole.operator)
    admin = make_user(db, email="admin_rec@crice.test", role=UserRole.compliance_admin)
    case = make_case(db, operator=op, stage=CaseStage.CLOSED, dossier_version=1)
    _row, cookies = make_session(db, admin)

    recall_reason = "Public registrar issued amended shareholder list contradicting prior finding."
    r = client.post(
        f"/cases/{case.id}/recall",
        data={
            "recall_reason": recall_reason,
            "reopen_to_stage": CaseStage.COLLECT.value,
            "_csrf": csrf_token_for(_row),
        },
        cookies=cookies,
        follow_redirects=False,
    )
    assert r.status_code == 302
    db.refresh(case)
    assert case.is_recalled is True
    assert case.dossier_version == 2
    assert case.stage == CaseStage.COLLECT.value


def test_non_admin_cannot_recall_case(client, db):
    """Operator cannot recall a closed case."""
    op = make_user(db, email="op_rec_denied@crice.test", role=UserRole.operator)
    case = make_case(db, operator=op, stage=CaseStage.CLOSED)
    _row, cookies = make_session(db, op)

    r = client.post(
        f"/cases/{case.id}/recall",
        data={
            "recall_reason": "Attempted recall by unauthorized operator user.",
            "reopen_to_stage": CaseStage.COLLECT.value,
            "_csrf": csrf_token_for(_row),
        },
        cookies=cookies,
        follow_redirects=False,
    )
    assert r.status_code == 403
