"""
app/claims/service.py – Atomic Claim Management, Citation Firewall, and Scoring Service.

Enforces server-side citation integrity, verbatim quote grounding, Indian entity resolution,
and bilateral separation of duties during CLAIM_EXTRACTION and CORRELATION_AND_SCORING.
"""
import datetime
import json
from typing import Any, Optional, Tuple

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.audit.writer import log_action
from app.claims.extractor import (
    extract_claims_from_accepted_records,
    extract_origin_domain,
    verify_verbatim_quote,
)
from app.claims.scoring import score_claim_entity_match
from app.models import (
    AIRun,
    AIRunStatus,
    Case,
    CaseStage,
    Claim,
    ExtractionMethod,
    MatchTier,
    Record,
    ReviewStatus,
    SourceReliability,
    TriageStatus,
    User,
    UserRole,
)


def _check_operator_permission(case: Case, user: User, action_desc: str):
    """Ensure user is active operator or compliance_admin and not the assigned reviewer."""
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user account.")
    if user.id == case.reviewer_id:
        raise HTTPException(
            status_code=403,
            detail=f"Bilateral separation violation: assigned reviewer cannot {action_desc}.",
        )
    if user.role not in (UserRole.operator.value, UserRole.compliance_admin.value):
        raise HTTPException(
            status_code=403,
            detail=f"Only an operator or compliance_admin may {action_desc}.",
        )


def _check_reviewer_permission(case: Case, user: User, action_desc: str):
    """Ensure user is active assigned reviewer (and not the case operator)."""
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Inactive user account.")
    if user.id == case.operator_id:
        raise HTTPException(
            status_code=403,
            detail=f"Bilateral separation violation: case operator cannot {action_desc}.",
        )
    if user.id != case.reviewer_id and user.role != UserRole.compliance_admin.value:
        raise HTTPException(
            status_code=403,
            detail=f"Only the assigned independent reviewer may {action_desc}.",
        )


def run_claim_extraction(
    db: Session,
    case: Case,
    operator: User,
    ip: str = "unknown",
) -> Tuple[AIRun, list[Claim]]:
    """
    Execute AI / deterministic extraction across ACCEPTED records for a case.
    Enforces strict citation firewall and quote grounding.
    """
    if case.stage != CaseStage.CLAIM_EXTRACTION.value:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot extract claims: case is in stage {case.stage}, expected CLAIM_EXTRACTION.",
        )
    _check_operator_permission(case, operator, "execute claim extraction")

    # Input Firewall: Query ONLY ACCEPTED records on this case
    accepted_records = (
        db.query(Record)
        .filter(Record.case_id == case.id, Record.triage_status == TriageStatus.ACCEPTED.value)
        .all()
    )

    if not accepted_records:
        if case.zero_findings_attested:
            # Bypass extraction cleanly when zero findings were attested
            now = datetime.datetime.now(datetime.timezone.utc)
            ai_run = AIRun(
                case_id=case.id,
                operator_id=operator.id,
                model_name="crice-bypassed",
                prompt_version="m4-v1.0",
                input_record_ids_json="[]",
                raw_prompt="Zero findings attested in Stage 3: extraction bypassed.",
                raw_output="[]",
                claims_extracted_count=0,
                claims_rejected_citation_count=0,
                status=AIRunStatus.BYPASSED.value,
                created_at=now,
            )
            db.add(ai_run)
            db.commit()
            db.refresh(ai_run)
            return ai_run, []
        else:
            raise HTTPException(
                status_code=400,
                detail="Cannot extract claims: zero ACCEPTED evidence records found on this case.",
            )

    model_name, raw_prompt, raw_output, candidate_claims, rejected_citations = extract_claims_from_accepted_records(
        case, accepted_records
    )

    now = datetime.datetime.now(datetime.timezone.utc)
    ai_run = AIRun(
        case_id=case.id,
        operator_id=operator.id,
        model_name=model_name,
        prompt_version="m4-v1.0",
        input_record_ids_json=json.dumps([r.id for r in accepted_records]),
        raw_prompt=raw_prompt,
        raw_output=raw_output,
        claims_extracted_count=0,
        claims_rejected_citation_count=rejected_citations,
        status=AIRunStatus.SUCCEEDED.value,
        created_at=now,
    )
    db.add(ai_run)
    db.flush()

    valid_record_map = {r.id: r for r in accepted_records}
    created_claims: list[Claim] = []

    for item in candidate_claims:
        pid = item.get("primary_record_id")
        # Citation Firewall: Must belong to ACCEPTED records on this case
        if pid not in valid_record_map:
            ai_run.claims_rejected_citation_count += 1
            continue

        primary_rec = valid_record_map[pid]
        supp_ids = [rid for rid in item.get("supporting_record_ids", [pid]) if rid in valid_record_map]
        if pid not in supp_ids:
            supp_ids.insert(0, pid)

        quote = item.get("verbatim_quote") or ""
        quote_ok = verify_verbatim_quote(quote, primary_rec.raw_content)

        extracted_ids = item.get("extracted_identifiers") or {}
        orig_domain = item.get("origin_domain") or extract_origin_domain(primary_rec.source_url)
        fg_key = item.get("finding_group_key") or "fg_general"

        claim = Claim(
            case_id=case.id,
            ai_run_id=ai_run.id,
            created_by_id=operator.id,
            extraction_method=ExtractionMethod.AI_EXTRACTED.value,
            subject_entity=item.get("subject_entity", case.subject_name).strip() or case.subject_name,
            predicate=item.get("predicate", "FACT_REPORTED").strip(),
            object_value=item.get("object_value", "").strip(),
            verbatim_quote=quote.strip() if quote else None,
            quote_verified=quote_ok,
            primary_record_id=pid,
            supporting_record_ids_json=json.dumps(supp_ids),
            snapshot_hash=primary_rec.snapshot_hash,
            extractor_version="m4-v1.0",
            extracted_identifiers_json=json.dumps(extracted_ids),
            matched_attributes_json="[]",
            match_tier=MatchTier.UNSCORED.value,
            source_reliability=primary_rec.source.default_reliability if primary_rec.source else "B",
            identity_confidence=6,
            is_adverse=bool(item.get("is_adverse", False)),
            adverse_category=item.get("adverse_category"),
            finding_group_key=fg_key,
            origin_domain=orig_domain,
            review_status=ReviewStatus.PENDING_REVIEW.value,
            created_at=now,
            updated_at=now,
        )

        # Pre-compute initial scoring
        tier, conf, attrs, rationale = score_claim_entity_match(case, claim)
        claim.match_tier = tier
        claim.identity_confidence = conf
        claim.matched_attributes_json = json.dumps(attrs)
        claim.scoring_rationale = rationale

        db.add(claim)
        created_claims.append(claim)

    ai_run.claims_extracted_count = len(created_claims)
    db.flush()

    log_action(
        db,
        action="claims_extracted",
        user_id=operator.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={
            "ai_run_id": ai_run.id,
            "model_name": model_name,
            "claims_count": len(created_claims),
            "rejected_citations": ai_run.claims_rejected_citation_count,
        },
        ip=ip,
        commit=True,
    )

    db.refresh(ai_run)
    for c in created_claims:
        db.refresh(c)

    return ai_run, created_claims


def create_manual_claim(
    db: Session,
    case: Case,
    operator: User,
    subject_entity: str,
    predicate: str,
    object_value: str,
    primary_record_id: int,
    verbatim_quote: Optional[str] = None,
    supporting_record_ids: Optional[list[int]] = None,
    is_adverse: bool = False,
    adverse_category: Optional[str] = None,
    finding_group_key: Optional[str] = None,
    ip: str = "unknown",
) -> Claim:
    """Manually author an atomic claim against an ACCEPTED evidence record."""
    if case.stage not in (CaseStage.CLAIM_EXTRACTION.value, CaseStage.CORRELATION_AND_SCORING.value):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot author claims in stage {case.stage}.",
        )
    _check_operator_permission(case, operator, "author manual claims")

    if not subject_entity.strip():
        raise HTTPException(status_code=400, detail="Subject entity is required.")
    if not predicate.strip():
        raise HTTPException(status_code=400, detail="Predicate is required.")
    if not object_value.strip():
        raise HTTPException(status_code=400, detail="Object value is required.")

    # Citation Firewall: Verify record belongs to case and is ACCEPTED
    primary_rec = (
        db.query(Record)
        .filter(
            Record.id == primary_record_id,
            Record.case_id == case.id,
            Record.triage_status == TriageStatus.ACCEPTED.value,
        )
        .first()
    )
    if not primary_rec:
        log_action(
            db,
            action="claim_creation_denied",
            user_id=operator.id,
            case_id=case.id,
            from_stage=case.stage,
            to_stage=case.stage,
            allowed=False,
            detail={"reason": f"Record {primary_record_id} is not an ACCEPTED evidence record for case {case.id}."},
            ip=ip,
            commit=True,
        )
        raise HTTPException(
            status_code=400,
            detail=f"Record {primary_record_id} is not an ACCEPTED evidence record for this case.",
        )

    supp_ids = [primary_record_id]
    if supporting_record_ids:
        valid_supp = (
            db.query(Record.id)
            .filter(
                Record.id.in_(supporting_record_ids),
                Record.case_id == case.id,
                Record.triage_status == TriageStatus.ACCEPTED.value,
            )
            .all()
        )
        supp_ids = list({primary_record_id, *(r[0] for r in valid_supp)})

    quote_ok = verify_verbatim_quote(verbatim_quote, primary_rec.raw_content) if verbatim_quote else False
    now = datetime.datetime.now(datetime.timezone.utc)
    orig_domain = extract_origin_domain(primary_rec.source_url)

    claim = Claim(
        case_id=case.id,
        ai_run_id=None,
        created_by_id=operator.id,
        extraction_method=ExtractionMethod.MANUAL.value,
        subject_entity=subject_entity.strip(),
        predicate=predicate.strip().upper(),
        object_value=object_value.strip(),
        verbatim_quote=verbatim_quote.strip() if verbatim_quote else None,
        quote_verified=quote_ok,
        primary_record_id=primary_rec.id,
        supporting_record_ids_json=json.dumps(supp_ids),
        snapshot_hash=primary_rec.snapshot_hash,
        extractor_version="m4-manual",
        extracted_identifiers_json="{}",
        matched_attributes_json="[]",
        match_tier=MatchTier.UNSCORED.value,
        source_reliability=primary_rec.source.default_reliability if primary_rec.source else "B",
        identity_confidence=6,
        is_adverse=is_adverse,
        adverse_category=adverse_category if is_adverse else None,
        finding_group_key=finding_group_key or "fg_manual",
        origin_domain=orig_domain,
        review_status=ReviewStatus.PENDING_REVIEW.value,
        created_at=now,
        updated_at=now,
    )

    tier, conf, attrs, rationale = score_claim_entity_match(case, claim)
    claim.match_tier = tier
    claim.identity_confidence = conf
    claim.matched_attributes_json = json.dumps(attrs)
    claim.scoring_rationale = rationale

    db.add(claim)
    db.commit()
    db.refresh(claim)

    log_action(
        db,
        action="claim_created_manual",
        user_id=operator.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={"claim_id": claim.id, "predicate": claim.predicate, "primary_record_id": primary_rec.id},
        ip=ip,
        commit=True,
    )

    return claim


def delete_claim(
    db: Session,
    case: Case,
    operator: User,
    claim_id: int,
    ip: str = "unknown",
):
    """Delete a draft claim during CLAIM_EXTRACTION."""
    if case.stage != CaseStage.CLAIM_EXTRACTION.value:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete claims in stage {case.stage}.",
        )
    _check_operator_permission(case, operator, "delete claims")

    claim = db.query(Claim).filter(Claim.id == claim_id, Claim.case_id == case.id).first()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found on this case.")

    db.delete(claim)
    db.commit()

    log_action(
        db,
        action="claim_deleted",
        user_id=operator.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={"claim_id": claim_id},
        ip=ip,
        commit=True,
    )


def run_entity_resolution_on_case(
    db: Session,
    case: Case,
    operator: User,
    ip: str = "unknown",
) -> list[Claim]:
    """Execute entity resolution and scoring across all claims on a case."""
    if case.stage != CaseStage.CORRELATION_AND_SCORING.value:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot run entity resolution in stage {case.stage}, expected CORRELATION_AND_SCORING.",
        )
    _check_operator_permission(case, operator, "run entity resolution")

    claims = db.query(Claim).filter(Claim.case_id == case.id).all()
    for c in claims:
        tier, conf, attrs, rationale = score_claim_entity_match(case, c)
        c.match_tier = tier
        c.identity_confidence = conf
        c.matched_attributes_json = json.dumps(attrs)
        c.scoring_rationale = rationale
        c.updated_at = datetime.datetime.now(datetime.timezone.utc)

    db.commit()

    log_action(
        db,
        action="entity_resolution_executed",
        user_id=operator.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={"scored_claims_count": len(claims)},
        ip=ip,
        commit=True,
    )

    for c in claims:
        db.refresh(c)
    return claims


def update_claim_scoring(
    db: Session,
    case: Case,
    operator: User,
    claim_id: int,
    match_tier: str,
    identity_confidence: int,
    is_adverse: bool,
    adverse_category: Optional[str] = None,
    finding_group_key: Optional[str] = None,
    source_reliability: Optional[str] = None,
    reliability_downgrade_reason: Optional[str] = None,
    ip: str = "unknown",
) -> Claim:
    """Update claim scoring parameters during CORRELATION_AND_SCORING."""
    if case.stage != CaseStage.CORRELATION_AND_SCORING.value:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot edit claim scoring in stage {case.stage}.",
        )
    _check_operator_permission(case, operator, "update claim scoring")

    claim = db.query(Claim).filter(Claim.id == claim_id, Claim.case_id == case.id).first()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found on this case.")

    clean_tier = match_tier.strip().upper()
    if clean_tier not in (m.value for m in MatchTier):
        raise HTTPException(status_code=400, detail=f"Invalid match tier: {match_tier!r}.")

    if not (1 <= identity_confidence <= 6):
        raise HTTPException(status_code=400, detail="Identity confidence must be an integer between 1 and 6.")

    # Reliability Downgrade Enforcement (Section 6.1)
    if source_reliability:
        clean_rel = source_reliability.strip().upper()
        if clean_rel not in (r.value for r in SourceReliability):
            raise HTTPException(status_code=400, detail=f"Invalid source reliability: {source_reliability!r}.")

        charter_rel = claim.primary_record.source.default_reliability if claim.primary_record and claim.primary_record.source else "B"
        # Ascii order comparison: 'A' < 'B' < 'C' ...
        if clean_rel < charter_rel:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot upgrade source reliability above charter tier {charter_rel} (attempted {clean_rel}).",
            )
        if clean_rel > charter_rel and (not reliability_downgrade_reason or len(reliability_downgrade_reason.strip()) < 5):
            raise HTTPException(
                status_code=400,
                detail="A downgrade reason of at least 5 characters is mandatory when lowering source reliability.",
            )
        claim.source_reliability = clean_rel
        claim.reliability_downgrade_reason = reliability_downgrade_reason.strip() if reliability_downgrade_reason else None

    # Adverse category validation
    valid_adverse_cats = {"FRAUD", "CONVICTION", "DEFAULT", "SANCTIONS", "LITIGATION_ACCUSED", "REGULATORY_PENALTY"}
    if is_adverse:
        if not adverse_category or adverse_category.strip().upper() not in valid_adverse_cats:
            raise HTTPException(
                status_code=400,
                detail=f"Adverse claims must specify an adverse category: {', '.join(sorted(valid_adverse_cats))}.",
            )
        claim.adverse_category = adverse_category.strip().upper()
    else:
        claim.adverse_category = None

    claim.match_tier = clean_tier
    claim.identity_confidence = identity_confidence
    claim.is_adverse = is_adverse
    if finding_group_key:
        claim.finding_group_key = finding_group_key.strip()
    claim.updated_at = datetime.datetime.now(datetime.timezone.utc)

    db.commit()
    db.refresh(claim)

    log_action(
        db,
        action="claim_scoring_updated",
        user_id=operator.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={
            "claim_id": claim.id,
            "match_tier": claim.match_tier,
            "identity_confidence": claim.identity_confidence,
            "source_reliability": claim.source_reliability,
            "is_adverse": claim.is_adverse,
        },
        ip=ip,
        commit=True,
    )

    return claim


def review_claim(
    db: Session,
    case: Case,
    reviewer: User,
    claim_id: int,
    review_status: str,
    review_note: Optional[str] = None,
    match_tier: Optional[str] = None,
    is_adverse: Optional[bool] = None,
    adverse_category: Optional[str] = None,
    finding_group_key: Optional[str] = None,
    ip: str = "unknown",
) -> Claim:
    """Independent Reviewer approval, edit, or rejection of an atomic claim."""
    if case.stage != CaseStage.INDEPENDENT_REVIEW.value:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot review claims in stage {case.stage}, expected INDEPENDENT_REVIEW.",
        )
    _check_reviewer_permission(case, reviewer, "review claims")

    claim = db.query(Claim).filter(Claim.id == claim_id, Claim.case_id == case.id).first()
    if not claim:
        raise HTTPException(status_code=404, detail="Claim not found on this case.")

    clean_status = review_status.strip().upper()
    if clean_status not in (ReviewStatus.APPROVED.value, ReviewStatus.REJECTED.value):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid review status: {review_status!r}. Must be APPROVED or REJECTED.",
        )

    clean_note = review_note.strip() if review_note else ""
    if clean_status == ReviewStatus.REJECTED.value and len(clean_note) < 5:
        raise HTTPException(
            status_code=400,
            detail="A review note of at least 5 characters is mandatory when rejecting a claim.",
        )

    # Reviewer modifications
    if match_tier:
        clean_tier = match_tier.strip().upper()
        if clean_tier in (m.value for m in MatchTier):
            claim.match_tier = clean_tier

    if is_adverse is not None:
        claim.is_adverse = is_adverse
        if is_adverse and adverse_category:
            claim.adverse_category = adverse_category.strip().upper()
        elif not is_adverse:
            claim.adverse_category = None

    if finding_group_key:
        claim.finding_group_key = finding_group_key.strip()

    now = datetime.datetime.now(datetime.timezone.utc)
    claim.review_status = clean_status
    claim.reviewed_by_id = reviewer.id
    claim.review_note = clean_note or None
    claim.reviewed_at = now
    claim.updated_at = now

    db.commit()
    db.refresh(claim)

    log_action(
        db,
        action="claim_reviewed",
        user_id=reviewer.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={
            "claim_id": claim.id,
            "review_status": claim.review_status,
            "review_note": claim.review_note,
        },
        ip=ip,
        commit=True,
    )

    return claim
