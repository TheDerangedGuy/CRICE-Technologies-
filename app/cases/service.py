"""
app/cases/service.py – business logic for case lifecycle.

Rules (from spec):
  create_case()
    - operator_id = acting user
    - stage = INTAKE, intake_approved = False
    - If subject_type == company → intake_approved = True automatically
    - case_ref = CRICE-<8 uppercase hex chars>, retry up to 10 times for uniqueness

  advance_case(case, user, to_stage, db, ip)
    - Must advance exactly one step forward (no skipping, no going back)
    - INTAKE → COLLECT requires intake_approved == True
    - RELEASE → CLOSED: only compliance_admin may advance
    - All other transitions: assigned operator (case.operator_id == user.id) OR compliance_admin
    - Denied attempts write action="advance_stage_denied" to audit log
    - Successful advances write action="advance_stage"

  approve_intake(case, user, db, ip)
    - Only compliance_admin may call this
    - Only applies to INTAKE stage cases with intake_approved == False (person subjects)
    - Writes action="intake_approved"

  assign_reviewer(case, acting_user, reviewer_id, db, ip)
    - Only compliance_admin may call this
    - Assignee must be active and have role == reviewer
    - reviewer.id != case.operator_id (no operator-as-reviewer conflict)
    - Denials write action="assign_reviewer_denied"
    - Successes write action="assign_reviewer" with old/new reviewer IDs in detail
"""
import secrets
from typing import Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.audit.writer import log_action
from app.models import (
    Case,
    PurposeEnum,
    STAGE_ORDER,
    StageEnum,
    SubjectType,
    User,
    UserRole,
)


# ── create_case ───────────────────────────────────────────────────────────────


def _generate_case_ref(db: Session) -> str:
    for _ in range(10):
        ref = f"CRICE-{secrets.token_hex(4).upper()}"
        if not db.query(Case).filter(Case.case_ref == ref).first():
            return ref
    raise RuntimeError("Could not generate a unique case_ref after 10 attempts")


def create_case(
    *,
    db: Session,
    acting_user: User,
    client_name: str,
    purpose: str,
    subject_type: str,
    subject_name: str,
    subject_identifier: Optional[str] = None,
    ip: str = "unknown",
) -> Case:
    intake_approved = subject_type == SubjectType.company.value

    case = Case(
        case_ref=_generate_case_ref(db),
        client_name=client_name,
        purpose=purpose,
        subject_type=subject_type,
        subject_name=subject_name,
        subject_identifier=subject_identifier or None,
        stage=StageEnum.INTAKE,
        intake_approved=intake_approved,
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
        detail={
            "case_ref": case.case_ref,
            "subject_type": subject_type,
            "intake_approved": intake_approved,
        },
        ip=ip,
    )
    db.commit()
    db.refresh(case)
    return case


# ── advance_case ──────────────────────────────────────────────────────────────


def _can_advance(case: Case, user: User) -> bool:
    """Return True if user is allowed to advance this case (not checking target stage)."""
    if user.role == UserRole.compliance_admin.value:
        return True
    return case.operator_id == user.id


def advance_case(
    case: Case,
    user: User,
    to_stage: str,
    db: Session,
    ip: str = "unknown",
) -> Case:
    """
    Advance `case` to `to_stage`.  Raises HTTPException(403) on denial.
    Every attempt (success or denial) is written to the audit log.
    """
    try:
        current_idx = STAGE_ORDER.index(case.stage)
        target_idx = STAGE_ORDER.index(to_stage)
    except ValueError:
        _deny(db, case, user, ip, "advance_stage_denied",
              f"Invalid stage value: {to_stage!r}")
        raise HTTPException(status_code=400, detail="Invalid stage.")

    # Must advance exactly one step forward
    if target_idx != current_idx + 1:
        _deny(db, case, user, ip, "advance_stage_denied",
              f"Cannot advance from {case.stage} to {to_stage} (not one step forward)")
        raise HTTPException(
            status_code=400,
            detail=f"You must advance the case one stage at a time.",
        )

    # Role / ownership check
    if not _can_advance(case, user):
        _deny(db, case, user, ip, "advance_stage_denied",
              "User is not the assigned operator or compliance_admin")
        raise HTTPException(status_code=403, detail="You can't advance this case.")

    # INTAKE → COLLECT: requires intake_approved
    if case.stage == StageEnum.INTAKE.value and not case.intake_approved:
        _deny(db, case, user, ip, "advance_stage_denied",
              "Intake not yet approved (person subject requires compliance_admin approval)")
        raise HTTPException(
            status_code=403,
            detail="Intake must be approved before moving to Collect.",
        )

    # RELEASE → CLOSED: only compliance_admin
    if case.stage == StageEnum.RELEASE.value and user.role != UserRole.compliance_admin.value:
        _deny(db, case, user, ip, "advance_stage_denied",
              "Only compliance_admin can close a case")
        raise HTTPException(
            status_code=403,
            detail="Only a Compliance Administrator can close a case.",
        )

    # Advance
    old_stage = case.stage
    case.stage = to_stage
    db.flush()

    log_action(
        db,
        action="advance_stage",
        user_id=user.id,
        case_id=case.id,
        detail={"from": old_stage, "to": to_stage},
        ip=ip,
    )
    db.commit()
    db.refresh(case)
    return case


def _deny(db: Session, case: Case, user: User, ip: str, action: str, reason: str) -> None:
    log_action(
        db,
        action=action,
        user_id=user.id,
        case_id=case.id,
        detail={"reason": reason},
        ip=ip,
    )
    db.commit()


# ── approve_intake ────────────────────────────────────────────────────────────


def approve_intake(case: Case, user: User, db: Session, ip: str = "unknown") -> Case:
    if user.role != UserRole.compliance_admin.value:
        log_action(db, action="intake_approved_denied", user_id=user.id,
                   case_id=case.id, detail={"reason": "Not compliance_admin"}, ip=ip)
        db.commit()
        raise HTTPException(status_code=403, detail="Only a Compliance Administrator can approve intake.")

    if case.stage != StageEnum.INTAKE.value:
        raise HTTPException(status_code=400, detail="Intake can only be approved in the INTAKE stage.")

    if case.intake_approved:
        raise HTTPException(status_code=400, detail="Intake already approved.")

    case.intake_approved = True
    db.flush()
    log_action(db, action="intake_approved", user_id=user.id, case_id=case.id, ip=ip)
    db.commit()
    db.refresh(case)
    return case


# ── assign_reviewer ───────────────────────────────────────────────────────────


def assign_reviewer(
    case: Case,
    acting_user: User,
    reviewer_id: int,
    db: Session,
    ip: str = "unknown",
) -> Case:
    def _deny_reviewer(reason: str):
        log_action(
            db,
            action="assign_reviewer_denied",
            user_id=acting_user.id,
            case_id=case.id,
            detail={"reason": reason, "reviewer_id": reviewer_id},
            ip=ip,
        )
        db.commit()

    # Only compliance_admin can assign
    if acting_user.role != UserRole.compliance_admin.value:
        _deny_reviewer("Acting user is not compliance_admin")
        raise HTTPException(status_code=403, detail="Only a Compliance Administrator can assign reviewers.")

    # Load the target reviewer
    reviewer: Optional[User] = db.get(User, reviewer_id)
    if not reviewer or not reviewer.is_active:
        _deny_reviewer("Reviewer not found or inactive")
        raise HTTPException(status_code=400, detail="Reviewer not found or inactive.")

    # Must have role == reviewer
    if reviewer.role != UserRole.reviewer.value:
        _deny_reviewer(f"Target user has role {reviewer.role!r}, not 'reviewer'")
        raise HTTPException(status_code=400, detail="The assigned user must have the reviewer role.")

    # No operator-as-reviewer conflict
    if reviewer.id == case.operator_id:
        _deny_reviewer("Reviewer is the same as the operator")
        raise HTTPException(status_code=400, detail="The operator of a case cannot also be its reviewer.")

    old_reviewer_id = case.reviewer_id
    case.reviewer_id = reviewer_id
    db.flush()

    log_action(
        db,
        action="assign_reviewer",
        user_id=acting_user.id,
        case_id=case.id,
        detail={"old_reviewer_id": old_reviewer_id, "new_reviewer_id": reviewer_id},
        ip=ip,
    )
    db.commit()
    db.refresh(case)
    return case
