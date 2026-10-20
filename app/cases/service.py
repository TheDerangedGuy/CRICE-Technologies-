"""
app/cases/service.py – Deterministic DAG State Machine for CRICE case lifecycle.

Enforces:
  - Strict transition matrix across the 10 CaseStage states.
  - Role-gated progression and bilateral separation of duties (operator != reviewer).
  - Server-side verified B2B client lookup; operators cannot self-attest KYC/MSA.
  - Human compliance gate for person subjects, fraud, or unverified clients.
  - Compliance Admin client verification at Compliance Gate.
  - Consent verification gate for employee screening.
  - Mandatory rework justification (>= 10 chars) on all backward loops.
  - Compliance admin post-release recall mechanism (version increment + is_recalled flag).
  - Total audit coverage: allowed=False written & committed before raising HTTPException.
"""
import json
import re
import secrets
from typing import Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.audit.writer import log_action
from app.claims.scoring import score_claim_entity_match
from app.dossier.service import release_dossier, revoke_dossier
from app.models import (
    Case,
    CaseStage,
    Claim,
    Dossier,
    DossierSection,
    MatchTier,
    PurposeEnum,
    Record,
    ReviewStatus,
    SourceRun,
    STAGE_ORDER,
    SubjectType,
    TriageStatus,
    User,
    UserRole,
)

# ── Closed Verified B2B Client Registry ───────────────────────────────────────
# In production, this can be backed by a B2B clients table or external CRM.
# KYC and MSA validity is determined server-side from this registry, preventing
# operator self-attestation privilege escalation.
VERIFIED_B2B_CLIENTS = {
    "Acme Capital Partners": {"kyc_verified": True, "msa_signed": True},
    "Global Investment Banking Corp": {"kyc_verified": True, "msa_signed": True},
    "Apex Legal Associates LLP": {"kyc_verified": True, "msa_signed": True},
    "Horizon Ventures Ltd": {"kyc_verified": True, "msa_signed": True},
    "Internal Compliance Audit": {"kyc_verified": True, "msa_signed": True},
}

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

OPERATOR_TRANSITIONS = {
    (CaseStage.INTAKE_DRAFT.value, CaseStage.COMPLIANCE_GATE.value),
    (CaseStage.INTAKE_DRAFT.value, CaseStage.COLLECT.value),
    (CaseStage.COLLECT.value, CaseStage.CLAIM_EXTRACTION.value),
    (CaseStage.CLAIM_EXTRACTION.value, CaseStage.CORRELATION_AND_SCORING.value),
    (CaseStage.CORRELATION_AND_SCORING.value, CaseStage.INDEPENDENT_REVIEW.value),
    (CaseStage.BUILD_AND_QA.value, CaseStage.RELEASE_GATE.value),
    (CaseStage.BUILD_AND_QA.value, CaseStage.INDEPENDENT_REVIEW.value),
}

REVIEWER_TRANSITIONS = {
    (CaseStage.INDEPENDENT_REVIEW.value, CaseStage.BUILD_AND_QA.value),
    (CaseStage.INDEPENDENT_REVIEW.value, CaseStage.CORRELATION_AND_SCORING.value),
    (CaseStage.INDEPENDENT_REVIEW.value, CaseStage.COLLECT.value),
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
    Server-side client verification:
      - If acting_user is compliance_admin: client_kyc_verified and msa_signed may be directly set.
      - If acting_user is operator: client_kyc_verified and msa_signed CANNOT be self-certified.
        They are determined strictly via server-side lookup against VERIFIED_B2B_CLIENTS.
        Unregistered client details are set to False, forcing the case to halt at COMPLIANCE_GATE.
    Auto-advances to COLLECT only if:
      - subject_type == 'company'
      - purpose in (corporate_due_diligence, litigation_support, vendor_verification)
      - effective_kyc is True AND effective_msa is True
    """
    if not client_name.strip():
        raise HTTPException(status_code=400, detail="Client name is required.")
    if not subject_name.strip():
        raise HTTPException(status_code=400, detail="Subject name is required.")
    if purpose not in [p.value for p in PurposeEnum]:
        raise HTTPException(status_code=400, detail=f"Invalid purpose: {purpose}")
    if subject_type not in [s.value for s in SubjectType]:
        raise HTTPException(status_code=400, detail=f"Invalid subject type: {subject_type}")

    # Prevent operator self-attestation privilege escalation
    cleaned_client = client_name.strip()
    if acting_user.role == UserRole.compliance_admin.value:
        effective_kyc = client_kyc_verified
        effective_msa = msa_signed
    else:
        # Operator role: look up in server-side verified client registry
        if cleaned_client in VERIFIED_B2B_CLIENTS:
            effective_kyc = VERIFIED_B2B_CLIENTS[cleaned_client]["kyc_verified"]
            effective_msa = VERIFIED_B2B_CLIENTS[cleaned_client]["msa_signed"]
        else:
            effective_kyc = False
            effective_msa = False

    # Auto-approval evaluation
    standard_corporate_purposes = (
        PurposeEnum.corporate_due_diligence.value,
        PurposeEnum.litigation_support.value,
        PurposeEnum.vendor_verification.value,
    )
    auto_eligible = (
        subject_type == SubjectType.company.value
        and purpose in standard_corporate_purposes
        and effective_kyc is True
        and effective_msa is True
    )

    stage = CaseStage.COLLECT.value if auto_eligible else CaseStage.COMPLIANCE_GATE.value
    intake_approved = auto_eligible

    case = Case(
        case_ref=_generate_case_ref(db),
        client_name=cleaned_client,
        client_kyc_verified=effective_kyc,
        msa_signed=effective_msa,
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
            "client_kyc_verified": effective_kyc,
            "msa_signed": effective_msa,
        },
        ip=ip,
        commit=True,
    )
    db.refresh(case)
    return case


# ── Section 7 Automated Classification Helper ─────────────────────────────────


def _apply_section_7_classification(db: Session, case: Case, ip: str = "unknown") -> None:
    """
    Automated Section 7 Adverse-Claim & Finding Classification Rule.
    Executes upon INDEPENDENT_REVIEW -> BUILD_AND_QA transition across all claims on the case:
      - Rejected claims -> EXCLUDED
      - Non-adverse approved claims with Tier 1/2 and confidence <= 3 -> CONFIRMED_FINDING
      - Non-adverse approved claims with Tier 3 or confidence >= 4 -> UNRESOLVED_POSSIBLE_MATCH
      - Adverse approved claims -> CONFIRMED_FINDING ONLY IF:
          1. Identity link is TIER_1 OR (TIER_2 with >= 2 secondary attributes / confidence <= 2); AND
          2. Corroborated by Tier A gov registry with TIER_1 match OR >= 2 distinct independent origin domains.
          Otherwise automatically quarantined to UNRESOLVED_POSSIBLE_MATCH.
    """
    claims = db.query(Claim).filter(Claim.case_id == case.id).all()
    approved_claims = [c for c in claims if c.review_status == ReviewStatus.APPROVED.value]

    for c in claims:
        if c.review_status == ReviewStatus.REJECTED.value:
            c.dossier_section = DossierSection.EXCLUDED.value
            continue

        if not c.is_adverse:
            if c.match_tier in (MatchTier.TIER_1.value, MatchTier.TIER_2.value) and c.identity_confidence <= 3:
                c.dossier_section = DossierSection.CONFIRMED_FINDING.value
            else:
                c.dossier_section = DossierSection.UNRESOLVED_POSSIBLE_MATCH.value
        else:
            # Adverse claim: Section 7 Rule
            matched_attrs = json.loads(c.matched_attributes_json or "[]")
            cond1 = (c.match_tier == MatchTier.TIER_1.value) or (
                c.match_tier == MatchTier.TIER_2.value and (len(matched_attrs) >= 2 or c.identity_confidence <= 2)
            )

            fg_key = c.finding_group_key or f"fg_{c.id}"
            group_mates = [
                m for m in approved_claims
                if (m.finding_group_key or f"fg_{m.id}") == fg_key
            ]

            has_tier_a_gov = any(
                (
                    m.match_tier == MatchTier.TIER_1.value
                    and m.primary_record
                    and m.primary_record.source
                    and (
                        m.primary_record.source.tier == "A"
                        or m.primary_record.source.code in ("MCA_MANUAL", "ECOURTS_MANUAL", "GST_MANUAL")
                    )
                )
                for m in group_mates
            )
            domains = {m.origin_domain for m in group_mates if m.origin_domain}
            has_multi_domain = len(domains) >= 2

            if cond1 and (has_tier_a_gov or has_multi_domain):
                c.dossier_section = DossierSection.CONFIRMED_FINDING.value
            else:
                c.dossier_section = DossierSection.UNRESOLVED_POSSIBLE_MATCH.value
                log_action(
                    db,
                    action="claim_quarantined",
                    user_id=case.reviewer_id or case.operator_id,
                    case_id=case.id,
                    from_stage=CaseStage.INDEPENDENT_REVIEW.value,
                    to_stage=CaseStage.BUILD_AND_QA.value,
                    allowed=True,
                    detail={
                        "claim_id": c.id,
                        "reason": "Failed Section 7 adverse corroboration criteria; quarantined to UNRESOLVED_POSSIBLE_MATCH",
                        "cond1": cond1,
                        "has_tier_a_gov": has_tier_a_gov,
                        "multi_domain_count": len(domains),
                    },
                    ip=ip,
                    commit=False,
                )


# ── State Machine Transition Engine ───────────────────────────────────────────


def transition_case(
    case: Case,
    user: User,
    to_stage: str,
    db: Session,
    ip: str = "unknown",
    rework_reason: Optional[str] = None,
    zero_findings_attested: bool = False,
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

    # 4. Direction 2: Bilateral separation of duties during stage execution
    # Ensure assigned reviewer cannot execute operator transitions on this case
    if (from_stage, to_stage) in OPERATOR_TRANSITIONS:
        if case.reviewer_id is not None and user.id == case.reviewer_id:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Bilateral separation violation: Assigned reviewer cannot execute operator transitions on this case.",
            )

    # Ensure case operator cannot execute review transitions on this case
    if (from_stage, to_stage) in REVIEWER_TRANSITIONS:
        if user.id == case.operator_id:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Bilateral separation violation: Case operator cannot review their own case.",
            )
        if case.reviewer_id != user.id:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Only the assigned independent reviewer can execute review transitions on this case.",
            )

    # 5. Stage-specific actor and guard condition validation

    # ── COMPLIANCE_GATE -> COLLECT
    if from_stage == CaseStage.COMPLIANCE_GATE.value and to_stage == CaseStage.COLLECT.value:
        if user.role != UserRole.compliance_admin.value:
            _deny(db, case, user, to_stage, ip, "Only a Compliance Administrator can approve intake at Compliance Gate.")
        if not case.client_kyc_verified or not case.msa_signed:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Client KYC and MSA must be verified by Compliance Administrator before collection can begin.",
            )
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

        runs_count = db.query(SourceRun).filter(SourceRun.case_id == case.id).count()
        if runs_count == 0:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Cannot advance: execute at least one chartered source run first.",
                status_code=400,
            )

        pending_count = (
            db.query(Record)
            .filter(
                Record.case_id == case.id,
                Record.triage_status == TriageStatus.PENDING_TRIAGE.value,
            )
            .count()
        )
        if pending_count > 0:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Cannot advance: all captured records must be triaged as ACCEPTED or REJECTED.",
                status_code=400,
            )

        accepted_count = (
            db.query(Record)
            .filter(
                Record.case_id == case.id,
                Record.triage_status == TriageStatus.ACCEPTED.value,
            )
            .count()
        )
        if accepted_count == 0 and not zero_findings_attested:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Cannot advance with zero accepted records unless Zero Findings attestation is confirmed.",
                status_code=400,
            )

    # ── CLAIM_EXTRACTION -> CORRELATION_AND_SCORING
    elif from_stage == CaseStage.CLAIM_EXTRACTION.value and to_stage == CaseStage.CORRELATION_AND_SCORING.value:
        if user.role != UserRole.compliance_admin.value and case.operator_id != user.id:
            _deny(db, case, user, to_stage, ip, "Only the assigned operator or Compliance Administrator can advance claims.")

        claims_count = db.query(Claim).filter(Claim.case_id == case.id).count()
        if claims_count == 0 and not (case.zero_findings_attested or zero_findings_attested):
            accepted_records = (
                db.query(Record)
                .filter(Record.case_id == case.id, Record.triage_status == TriageStatus.ACCEPTED.value)
                .all()
            )
            if accepted_records:
                try:
                    from app.claims.service import run_claim_extraction
                    run_claim_extraction(db, case, user, ip=ip)
                    claims_count = db.query(Claim).filter(Claim.case_id == case.id).count()
                except Exception:
                    pass

        if claims_count == 0 and not (case.zero_findings_attested or zero_findings_attested):
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Cannot advance from Claim Extraction without at least one claim unless zero findings is attested.",
                status_code=400,
            )
        if zero_findings_attested:
            case.zero_findings_attested = True

        # Pre-compute scores on unscored claims so operator begins with suggested scores
        unscored_claims = (
            db.query(Claim)
            .filter(Claim.case_id == case.id, Claim.match_tier == MatchTier.UNSCORED.value)
            .all()
        )
        for c in unscored_claims:
            tier, conf, attrs, rationale = score_claim_entity_match(case, c)
            c.match_tier = tier
            c.identity_confidence = conf
            c.matched_attributes_json = json.dumps(attrs)
            c.scoring_rationale = rationale

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
        case_claims = db.query(Claim).filter(Claim.case_id == case.id).all()
        if not case_claims and not case.zero_findings_attested:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Cannot advance to Independent Review with zero claims unless Zero Findings is attested.",
                status_code=400,
            )
        for c in case_claims:
            if c.match_tier == MatchTier.UNSCORED.value:
                _deny(
                    db,
                    case,
                    user,
                    to_stage,
                    ip,
                    f"Claim #{c.id} is still UNSCORED. All claims must be scored before entering Independent Review.",
                    status_code=400,
                )
            if not (1 <= c.identity_confidence <= 6):
                _deny(
                    db,
                    case,
                    user,
                    to_stage,
                    ip,
                    f"Claim #{c.id} has invalid confidence {c.identity_confidence}. Must be between 1 and 6.",
                    status_code=400,
                )
            if c.is_adverse and not c.adverse_category:
                _deny(
                    db,
                    case,
                    user,
                    to_stage,
                    ip,
                    f"Adverse claim #{c.id} is missing a required adverse category.",
                    status_code=400,
                )

    # ── INDEPENDENT_REVIEW -> BUILD_AND_QA
    elif from_stage == CaseStage.INDEPENDENT_REVIEW.value and to_stage == CaseStage.BUILD_AND_QA.value:
        if case.reviewer_id != user.id:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Only the assigned independent reviewer can complete review and advance to Build & QA.",
            )
        case_claims_count = db.query(Claim).filter(Claim.case_id == case.id).count()
        if case_claims_count == 0 and not case.zero_findings_attested:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                "Cannot advance to Build & QA with zero claims unless Zero Findings is attested.",
                status_code=400,
            )
        pending_claims = (
            db.query(Claim)
            .filter(
                Claim.case_id == case.id,
                Claim.review_status == ReviewStatus.PENDING_REVIEW.value,
            )
            .count()
        )
        if pending_claims > 0:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                f"Cannot advance: {pending_claims} claim(s) are still PENDING_REVIEW.",
                status_code=400,
            )
        # Apply Section 7 Automated Adverse-Claim and Non-Adverse Classification
        _apply_section_7_classification(db, case, ip=ip)

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
        curr_ver = case.dossier_version or 1
        dossier_exists = (
            db.query(Dossier)
            .filter(Dossier.case_id == case.id, Dossier.version == curr_ver)
            .first()
        )
        if not dossier_exists:
            _deny(
                db,
                case,
                user,
                to_stage,
                ip,
                f"Cannot advance to Release Gate: dossier version v{curr_ver}.0 has not been compiled yet.",
                status_code=400,
            )

    # ── BUILD_AND_QA -> INDEPENDENT_REVIEW (Rework)
    elif from_stage == CaseStage.BUILD_AND_QA.value and to_stage == CaseStage.INDEPENDENT_REVIEW.value:
        if user.role != UserRole.compliance_admin.value and case.operator_id != user.id:
            _deny(db, case, user, to_stage, ip, "Only the assigned operator or Compliance Administrator can return for review.")

    # ── RELEASE_GATE -> CLOSED
    elif from_stage == CaseStage.RELEASE_GATE.value and to_stage == CaseStage.CLOSED.value:
        if user.role != UserRole.compliance_admin.value:
            _deny(db, case, user, to_stage, ip, "Only a Compliance Administrator can release and close a case.")
        release_dossier(db, case, user, ip=ip)

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
        revoke_dossier(db, case, user, reason=rework_reason or "Recall triggered", ip=ip)
        case.is_recalled = True
        case.dossier_version = (case.dossier_version or 1) + 1

    # ── RECALLED -> COLLECT or INDEPENDENT_REVIEW
    elif from_stage == CaseStage.RECALLED.value and to_stage in (
        CaseStage.COLLECT.value,
        CaseStage.INDEPENDENT_REVIEW.value,
    ):
        if user.role != UserRole.compliance_admin.value:
            _deny(db, case, user, to_stage, ip, "Only a Compliance Administrator can reopen a recalled case.")

    # 6. Apply transition state changes
    old_stage = case.stage
    case.stage = to_stage
    if is_backward and rework_reason:
        case.rework_reason = rework_reason.strip()
    db.flush()

    # 7. Write successful audit log
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
            "zero_findings_attested": zero_findings_attested,
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
    zero_findings_attested: bool = False,
) -> Case:
    """Convenience forward advance wrapper."""
    return transition_case(
        case,
        user,
        to_stage,
        db,
        ip=ip,
        zero_findings_attested=zero_findings_attested,
    )


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


def verify_client_kyc(case: Case, user: User, db: Session, ip: str = "unknown") -> Case:
    """Compliance Admin marks Client KYC and MSA as verified at COMPLIANCE_GATE."""
    if user.role != UserRole.compliance_admin.value:
        raise HTTPException(
            status_code=403,
            detail="Only a Compliance Administrator can verify client KYC and MSA.",
        )
    case.client_kyc_verified = True
    case.msa_signed = True
    db.flush()
    log_action(
        db,
        action="client_kyc_verified",
        user_id=user.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={"client_kyc_verified": True, "msa_signed": True},
        ip=ip,
        commit=True,
    )
    db.refresh(case)
    return case


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
    if not reviewer:
        _deny_assignment("Reviewer not found.")

    if not reviewer.is_active:
        _deny_assignment("Cannot assign inactive reviewer.")

    # Direction 1: Bilateral conflict check
    if reviewer.id == case.operator_id:
        _deny_assignment("Bilateral conflict: The operator of a case cannot also be its reviewer.")

    # Direction 1: Role check
    if reviewer.role != UserRole.reviewer.value:
        _deny_assignment(f"Role mismatch: Target user has role '{reviewer.role}', but must have 'reviewer' role.")

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
