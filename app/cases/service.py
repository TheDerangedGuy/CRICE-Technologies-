"""
app/cases/service.py – Deterministic DAG State Machine for CRICE case lifecycle.

Enforces:
  - Strict transition matrix across the 10 CaseStage states.
  - Role-gated progression and bilateral separation of duties (operator != reviewer).
  - Auto-advance on company intake with verified KYC and MSA.
  - Human compliance gate for person subjects, fraud, or unverified clients.
  - Consent verification gate for employee screening.
  - Mandatory rework justification (>= 10 chars) on all backward loops.
  - Compliance admin post-release recall mechanism (version increment + is_recalled flag).
  - Total audit coverage: allowed=False written & committed before raising HTTPException.
"""
import re
import secrets
from typing import Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.audit.writer import log_action
from app.models import (
    Case,
    CaseStage,
    PurposeEnum,
    STAGE_ORDER,
    SubjectType,
    User,
    UserRole,
)

# ── Valid Transitions Matrix ──────────────────────────────────────────────────

ALLOWED_TRANSITIONS = {
    CaseStage.INTAKE_DRAFT.value: [
        CaseStage.COMPLIANCE_GATE.value,
        CaseStage.COLLECT.value,  # Auto-advance path only
    ],
    CaseStage.COMPLIANCE_GATE.value: [
        CaseStage.COLLECT.value,
        CaseStage.INTAKE_DRAFT.value,  # Rework
    ],
    CaseStage.COLLECT.value: [
        CaseStage.CLAIM_EXTRACTION.value,
    ],
    CaseStage.CLAIM_EXTRACTION.value: [
        CaseStage.CORRELATION_AND_SCORING.value,
    ],
    CaseStage.CORRELATION_AND_SCORING.value: [
        CaseStage.INDEPENDENT_REVIEW.value,
    ],
    CaseStage.INDEPENDENT_REVIEW.value: [
        CaseStage.BUILD_AND_QA.value,
        CaseStage.CORRELATION_AND_SCORING.value,  # Rework
        CaseStage.COLLECT.value,                  # Rework
    ],
    CaseStage.BUILD_AND_QA.value: [
        CaseStage.RELEASE_GATE.value,
        CaseStage.INDEPENDENT_REVIEW.value,       # Rework
    ],
    CaseStage.RELEASE_GATE.value: [
        CaseStage.CLOSED.value,
        CaseStage.BUILD_AND_QA.value,             # Rework
        CaseStage.INDEPENDENT_REVIEW.value,       # Rework
    ],
    CaseStage.CLOSED.value: [
        CaseStage.RECALLED.value,
    ],
    CaseStage.RECALLED.value: [
        CaseStage.COLLECT.value,
        CaseStage.INDEPENDENT_REVIEW.value,
    ],
}

BACKWARD_TRANSITIONS = {
    (CaseStage.COMPLIANCE_GATE.value, CaseStage.INTAKE_DRAFT.value),
    (CaseStage.INDEPENDENT_REVIEW.value, CaseStage.CORRELATION_AND_SCORING.value),
    (CaseStage.INDEPENDENT_REVIEW.value, CaseStage.COLLECT.value),
    (CaseStage.BUILD_AND_QA.value, CaseStage.INDEPENDENT_REVIEW.value),
    (CaseStage.RELEASE_GATE.value, CaseStage.BUILD_AND_QA.value),
    (CaseStage.RELEASE_GATE.value, CaseStage.INDEPENDENT_REVIEW.value),
    (CaseStage.CLOSED.value, CaseStage.RECALLED.value),
}


# ── Audit Denial Helper ───────────────────────────────────────────────────────


def _deny(
    db: Session,
    case: Case,
    user: User,
    to_stage: str,
    ip: str,
    reason: str,
    status_code: int = 403,
) -> None:
    """Log denial with allowed=False and commit immediately before raising exception."""
    log_action(
        db,
        action="transition_denied",
        user_id=user.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=to_stage,
        allowed=False,
        detail={"reason": reason},
        ip=ip,
        commit=True,
    )
    raise HTTPException(status_code=status_code, detail=reason)


# ── Case Ref Generator ────────────────────────────────────────────────────────


def _generate_case_ref(db: Session) -> str:
    """Generates unique 14-char case_ref matching ^CRICE-[0-9A-F]{8}$."""
    for _ in range(20):
        ref = f"CRICE-{secrets.token_hex(4).upper()}"
        if not db.query(Case).filter(Case.case_ref == ref).first():
            return ref
    raise RuntimeError("Could not generate unique case_ref after 20 attempts")


# ── Create Case ───────────────────────────────────────────────────────────────


def create_case(
    *,
    db: Session,
    acting_user: User,
    client_name: str,
    purpose: str,
    subject_type: str,
    subject_name: str,
    subject_identifier: Optional[str] = None,
    client_kyc_verified: bool = False,
    msa_signed: bool = False,
    ip: str = "unknown",
) -> Case:
    """
    Drafts a new case and evaluates auto-advance eligibility.
    Auto-advances to COLLECT only if:
      - subject_type == 'company'
      - purpose in (corporate_due_diligence, litigation_support, vendor_verification)
      - client_kyc_verified is True AND msa_signed is True
    Otherwise places the case in COMPLIANCE_GATE.
    """
    if not client_name.strip():
        raise HTTPException(status_code=400, detail="Client name is required.")
    if not subject_name.strip():
        raise HTTPException(status_code=400, detail="Subject name is required.")
    if purpose not in [p.value for p in PurposeEnum]:
        raise HTTPException(status_code=400, detail=f"Invalid purpose: {purpose}")
    if subject_type not in [s.value for s in SubjectType]:
        raise HTTPException(status_code=400, detail=f"Invalid subject type: {subject_type}")

    # Auto-approval evaluation
    standard_corporate_purposes = (
        PurposeEnum.corporate_due_diligence.value,
        PurposeEnum.litigation_support.value,
        PurposeEnum.vendor_verification.value,
    )
    auto_eligible = (
        subject_type == SubjectType.company.value
        and purpose in standard_corporate_purposes
        and client_kyc_verified is True
        and msa_signed is True
    )

    stage = CaseStage.COLLECT.value if auto_eligible else CaseStage.COMPLIANCE_GATE.value
    intake_approved = auto_eligible

    case = Case(
        case_ref=_generate_case_ref(db),
        client_name=client_name.strip(),
        client_kyc_verified=client_kyc_verified,
        msa_signed=msa_signed,
        purpose=purpose,
        subject_type=subject_type,
        subject_name=subject_name.strip(),
        subject_identifier=subject_identifier.strip() if subject_identifier else None,
        stage=stage,
        intake_approved=intake_approved,
        consent_verified=False,
        dossier_version=1,
        is_recalled=False,
        operator_id=acting_user.id,
        created_by=acting_user.id,
    )
    db.add(case)
    db.flush()

    log_action(
        db,
        action="case_created",
        user_id=acting_user.id,
        case_id=case.id,
        from_stage=CaseStage.INTAKE_DRAFT.value,
        to_stage=stage,
        allowed=True,
        detail={
            "case_ref": case.case_ref,
            "subject_type": subject_type,
            "purpose": purpose,
            "auto_advanced": auto_eligible,
            "intake_approved": intake_approved,
        },
        ip=ip,
        commit=True,
    )
    db.refresh(case)
    return case


# ── State Machine Transition Engine ───────────────────────────────────────────


def transition_case(
    case: Case,
    user: User,
    to_stage: str,
    db: Session,
    ip: str = "unknown",
    rework_reason: Optional[str] = None,
) -> Case:
    """
    Central DAG transition engine enforcing all state rules, actor authorizations,
    guard conditions, and audit logging.
    """
    from_stage = case.stage

    # 1. Validate stage existence
    valid_stages = [s.value for s in CaseStage]
    if to_stage not in valid_stages:
        _deny(db, case, user, to_stage, ip, f"Invalid target stage: {to_stage}", status_code=400)

    # 2. Check transition graph validity
    allowed_targets = ALLOWED_TRANSITIONS.get(from_stage, [])
    if to_stage not in allowed_targets:
        _deny(
            db,
            case,
            user,
            to_stage,
            ip,
            f"Invalid stage transition from {from_stage} to {to_stage}. Stage skipping is prohibited.",
            status_code=400,
        )

    # 3. Check rework justification on backward transitions
    is_backward = (from_stage, to_stage) in BACKWARD_TRANSITIONS
    if is_backward:
        if not rework_reason or len(rework_reason.strip()) < 10:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "A mandatory rework justification of at least 10 characters is required.",
                status_code=400,
            )

    # 4. Stage-specific actor and guard condition validation

    # ── COMPLIANCE_GATE -> COLLECT
    if from_stage == CaseStage.COMPLIANCE_GATE.value and to_stage == CaseStage.COLLECT.value:
        if user.role != UserRole.compliance_admin.value:
            _deny(db, case, user, to_stage, ip, "Only a Compliance Administrator can approve intake at Compliance Gate.")
        if case.purpose == PurposeEnum.employee_screening_with_consent.value and not case.consent_verified:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Employee screening requires verified consent (consent_verified = True) before intake approval.",
            )
        case.intake_approved = True

    # ── COMPLIANCE_GATE -> INTAKE_DRAFT (Rework)
    elif from_stage == CaseStage.COMPLIANCE_GATE.value and to_stage == CaseStage.INTAKE_DRAFT.value:
        if user.role != UserRole.compliance_admin.value:
            _deny(db, case, user, to_stage, ip, "Only a Compliance Administrator can return a case to Intake Draft.")

    # ── COLLECT -> CLAIM_EXTRACTION
    elif from_stage == CaseStage.COLLECT.value and to_stage == CaseStage.CLAIM_EXTRACTION.value:
        if user.role != UserRole.compliance_admin.value and case.operator_id != user.id:
            _deny(db, case, user, to_stage, ip, "Only the assigned operator or Compliance Administrator can advance collection.")

    # ── CLAIM_EXTRACTION -> CORRELATION_AND_SCORING
    elif from_stage == CaseStage.CLAIM_EXTRACTION.value and to_stage == CaseStage.CORRELATION_AND_SCORING.value:
        if user.role != UserRole.compliance_admin.value and case.operator_id != user.id:
            _deny(db, case, user, to_stage, ip, "Only the assigned operator or Compliance Administrator can advance claims.")

    # ── CORRELATION_AND_SCORING -> INDEPENDENT_REVIEW
    elif from_stage == CaseStage.CORRELATION_AND_SCORING.value and to_stage == CaseStage.INDEPENDENT_REVIEW.value:
        if user.role != UserRole.compliance_admin.value and case.operator_id != user.id:
            _deny(db, case, user, to_stage, ip, "Only the assigned operator or Compliance Administrator can advance to Independent Review.")
        if not case.reviewer_id:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "A reviewer must be assigned by Compliance Administrator before entering Independent Review.",
            )
        if case.reviewer_id == case.operator_id:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Bilateral separation of duties violation: reviewer cannot be the case operator.",
            )

    # ── INDEPENDENT_REVIEW -> BUILD_AND_QA
    elif from_stage == CaseStage.INDEPENDENT_REVIEW.value and to_stage == CaseStage.BUILD_AND_QA.value:
        # Strictly restricted to the assigned reviewer (bilateral separation)
        if case.reviewer_id != user.id:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Only the assigned independent reviewer can complete review and advance to Build & QA.",
            )

    # ── INDEPENDENT_REVIEW -> Rework (COLLECT or CORRELATION_AND_SCORING)
    elif from_stage == CaseStage.INDEPENDENT_REVIEW.value and to_stage in (
        CaseStage.CORRELATION_AND_SCORING.value,
        CaseStage.COLLECT.value,
    ):
        if case.reviewer_id != user.id and user.role != UserRole.compliance_admin.value:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Only the assigned reviewer or Compliance Administrator can return a case for rework.",
            )

    # ── BUILD_AND_QA -> RELEASE_GATE
    elif from_stage == CaseStage.BUILD_AND_QA.value and to_stage == CaseStage.RELEASE_GATE.value:
        if user.role != UserRole.compliance_admin.value and case.operator_id != user.id:
            _deny(db, case, user, to_stage, ip, "Only the assigned operator or Compliance Administrator can submit for release.")

    # ── BUILD_AND_QA -> INDEPENDENT_REVIEW (Rework)
    elif from_stage == CaseStage.BUILD_AND_QA.value and to_stage == CaseStage.INDEPENDENT_REVIEW.value:
        if user.role != UserRole.compliance_admin.value and case.operator_id != user.id:
            _deny(db, case, user, to_stage, ip, "Only the assigned operator or Compliance Administrator can return for review.")

    # ── RELEASE_GATE -> CLOSED
    elif from_stage == CaseStage.RELEASE_GATE.value and to_stage == CaseStage.CLOSED.value:
        if user.role != UserRole.compliance_admin.value:
            _deny(db, case, user, to_stage, ip, "Only a Compliance Administrator can release and close a case.")

    # ── RELEASE_GATE -> Rework (BUILD_AND_QA or INDEPENDENT_REVIEW)
    elif from_stage == CaseStage.RELEASE_GATE.value and to_stage in (
        CaseStage.BUILD_AND_QA.value,
        CaseStage.INDEPENDENT_REVIEW.value,
    ):
        if user.role != UserRole.compliance_admin.value:
            _deny(db, case, user, to_stage, ip, "Only a Compliance Administrator can return a case for rework from Release Gate.")

    # ── CLOSED -> RECALLED
    elif from_stage == CaseStage.CLOSED.value and to_stage == CaseStage.RECALLED.value:
        if user.role != UserRole.compliance_admin.value:
            _deny(db, case, user, to_stage, ip, "Only a Compliance Administrator can recall a closed case.")
        case.is_recalled = True
        case.dossier_version = (case.dossier_version or 1) + 1

    # ── RECALLED -> COLLECT or INDEPENDENT_REVIEW
    elif from_stage == CaseStage.RECALLED.value and to_stage in (
        CaseStage.COLLECT.value,
        CaseStage.INDEPENDENT_REVIEW.value,
    ):
        if user.role != UserRole.compliance_admin.value:
            _deny(db, case, user, to_stage, ip, "Only a Compliance Administrator can reopen a recalled case.")

    # 5. Apply transition state changes
    old_stage = case.stage
    case.stage = to_stage
    if is_backward and rework_reason:
        case.rework_reason = rework_reason.strip()
    db.flush()

    # 6. Write successful audit log
    log_action(
        db,
        action="advance_stage" if not is_backward else "rework_stage",
        user_id=user.id,
        case_id=case.id,
        from_stage=old_stage,
        to_stage=to_stage,
        allowed=True,
        detail={
            "from": old_stage,
            "to": to_stage,
            "rework_reason": rework_reason if is_backward else None,
            "dossier_version": case.dossier_version,
            "is_recalled": case.is_recalled,
        },
        ip=ip,
        commit=True,
    )
    db.refresh(case)
    return case


# ── Convenience Wrappers ──────────────────────────────────────────────────────


def advance_case(
    case: Case,
    user: User,
    to_stage: str,
    db: Session,
    ip: str = "unknown",
) -> Case:
    """Convenience forward advance wrapper."""
    return transition_case(case, user, to_stage, db, ip=ip)


def rework_case(
    case: Case,
    user: User,
    to_stage: str,
    rework_reason: str,
    db: Session,
    ip: str = "unknown",
) -> Case:
    """Convenience backward rework wrapper."""
    return transition_case(case, user, to_stage, db, ip=ip, rework_reason=rework_reason)


def recall_case(
    case: Case,
    user: User,
    recall_reason: str,
    reopen_to_stage: str,
    db: Session,
    ip: str = "unknown",
) -> Case:
    """
    Executes full recall sequence: CLOSED -> RECALLED -> reopen_to_stage
    Increments dossier_version, sets is_recalled=True, logs recall justification.
    """
    if reopen_to_stage not in (CaseStage.COLLECT.value, CaseStage.INDEPENDENT_REVIEW.value):
        raise HTTPException(
            status_code=400,
            detail="A recalled case can only be reopened in COLLECT or INDEPENDENT_REVIEW.",
        )
    # Step 1: CLOSED -> RECALLED
    transition_case(case, user, CaseStage.RECALLED.value, db, ip=ip, rework_reason=recall_reason)
    # Step 2: RECALLED -> reopen_to_stage
    return transition_case(case, user, reopen_to_stage, db, ip=ip)


def approve_intake(case: Case, user: User, db: Session, ip: str = "unknown") -> Case:
    """Compliance Admin approval at COMPLIANCE_GATE."""
    return transition_case(case, user, CaseStage.COLLECT.value, db, ip=ip)


def verify_consent(case: Case, user: User, db: Session, ip: str = "unknown") -> Case:
    """Marks subject consent as verified (required for employee screening)."""
    if user.role != UserRole.compliance_admin.value:
        raise HTTPException(status_code=403, detail="Only a Compliance Administrator can verify consent.")
    case.consent_verified = True
    db.flush()
    log_action(
        db,
        action="consent_verified",
        user_id=user.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={"consent_verified": True},
        ip=ip,
        commit=True,
    )
    db.refresh(case)
    return case


def assign_reviewer(
    case: Case,
    acting_user: User,
    reviewer_id: int,
    db: Session,
    ip: str = "unknown",
) -> Case:
    """Assigns an independent reviewer to the case (compliance_admin only)."""
    def _deny_assignment(reason: str):
        log_action(
            db,
            action="assign_reviewer_denied",
            user_id=acting_user.id,
            case_id=case.id,
            from_stage=case.stage,
            to_stage=case.stage,
            allowed=False,
            detail={"reason": reason, "reviewer_id": reviewer_id},
            ip=ip,
            commit=True,
        )
        raise HTTPException(status_code=400, detail=reason)

    if acting_user.role != UserRole.compliance_admin.value:
        log_action(
            db,
            action="assign_reviewer_denied",
            user_id=acting_user.id,
            case_id=case.id,
            from_stage=case.stage,
            to_stage=case.stage,
            allowed=False,
            detail={"reason": "Acting user is not compliance_admin"},
            ip=ip,
            commit=True,
        )
        raise HTTPException(status_code=403, detail="Only a Compliance Administrator can assign reviewers.")

    reviewer = db.get(User, reviewer_id)
    if not reviewer or not reviewer.is_active:
        _deny_assignment("Reviewer not found or inactive.")

    if reviewer.id == case.operator_id:
        _deny_assignment("Bilateral conflict: The operator of a case cannot also be its reviewer.")

    if reviewer.role != UserRole.reviewer.value:
        _deny_assignment("The assigned user must have the reviewer role.")

    old_reviewer_id = case.reviewer_id
    case.reviewer_id = reviewer_id
    db.flush()

    log_action(
        db,
        action="assign_reviewer",
        user_id=acting_user.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={"old_reviewer_id": old_reviewer_id, "new_reviewer_id": reviewer_id},
        ip=ip,
        commit=True,
    )
    db.refresh(case)
    return case
