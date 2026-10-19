"""
app/collect/service.py – Collection and Triage Service Layer.

Handles automated RDAP execution, tamper-evident manual capture against
chartered sources, immutable record hashing, and inline record triage.
Enforces strict server-side permissions and logs all actions to the audit log.
"""
import datetime
import hashlib
from typing import Optional, Tuple

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.audit.writer import log_action
from app.collect.rdap import fetch_domain_rdap, normalize_and_validate_domain
from app.models import (
    Case,
    CaseStage,
    CollectionMode,
    Record,
    SourceCharter,
    SourceRun,
    SourceRunStatus,
    TriageStatus,
    User,
    UserRole,
)


def _check_operator_permission(case: Case, user: User, action_desc: str):
    """Ensure acting user is operator or admin and not the assigned reviewer."""
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


def execute_domain_rdap(
    db: Session,
    case: Case,
    operator: User,
    domain: str,
    ip: Optional[str] = None,
) -> Tuple[SourceRun, Optional[Record]]:
    """Execute automated Domain RDAP reconnaissance and store hashed snapshot if found."""
    if case.stage != CaseStage.COLLECT.value:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot run collection: case is in stage {case.stage}, expected COLLECT.",
        )
    _check_operator_permission(case, operator, "execute domain RDAP collection")

    charter = (
        db.query(SourceCharter)
        .filter(SourceCharter.code == "DOMAIN_RDAP", SourceCharter.is_active.is_(True))
        .first()
    )
    if not charter:
        raise HTTPException(
            status_code=500,
            detail="Source charter DOMAIN_RDAP is not configured or inactive.",
        )

    try:
        clean_domain = normalize_and_validate_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    started_at = datetime.datetime.now(datetime.timezone.utc)
    result = fetch_domain_rdap(clean_domain)
    completed_at = datetime.datetime.now(datetime.timezone.utc)

    source_run = SourceRun(
        case_id=case.id,
        source_id=charter.id,
        operator_id=operator.id,
        query_input=clean_domain,
        status=result.status,
        error_detail=result.error_detail,
        started_at=started_at,
        completed_at=completed_at,
    )
    db.add(source_run)
    db.flush()

    record = None
    if result.status == SourceRunStatus.FOUND.value and result.raw_content and result.snapshot_hash:
        record = Record(
            case_id=case.id,
            source_run_id=source_run.id,
            source_id=charter.id,
            title=f"Domain RDAP: {clean_domain}",
            source_url=result.source_url,
            raw_content=result.raw_content,
            content_type="application/json",
            snapshot_hash=result.snapshot_hash,
            extractor_version="m2-v1.0",
            retrieved_at=completed_at,
            triage_status=TriageStatus.PENDING_TRIAGE.value,
        )
        db.add(record)
        db.flush()

    log_action(
        db,
        action="source_run_rdap",
        user_id=operator.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={
            "source_code": "DOMAIN_RDAP",
            "domain": clean_domain,
            "status": result.status,
            "source_run_id": source_run.id,
            "record_id": record.id if record else None,
            "snapshot_hash": record.snapshot_hash if record else None,
            "error_detail": result.error_detail,
        },
        ip=ip,
    )
    db.commit()
    db.refresh(source_run)
    if record:
        db.refresh(record)
    return source_run, record


def execute_manual_capture(
    db: Session,
    case: Case,
    operator: User,
    source_code: str,
    query_input: str,
    outcome: str,
    title: Optional[str] = None,
    source_url: Optional[str] = None,
    raw_content: Optional[str] = None,
    content_type: str = "text/plain",
    ip: Optional[str] = None,
) -> Tuple[SourceRun, Optional[Record]]:
    """Store tamper-evident manual capture from an active MANUAL_CAPTURE chartered source."""
    if case.stage != CaseStage.COLLECT.value:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot capture evidence: case is in stage {case.stage}, expected COLLECT.",
        )
    _check_operator_permission(case, operator, "submit manual evidence capture")

    charter = (
        db.query(SourceCharter)
        .filter(SourceCharter.code == source_code, SourceCharter.is_active.is_(True))
        .first()
    )
    if not charter:
        raise HTTPException(
            status_code=400,
            detail=f"Unrecognized or inactive source charter code: {source_code!r}.",
        )
    if charter.collection_mode != CollectionMode.MANUAL_CAPTURE.value:
        raise HTTPException(
            status_code=400,
            detail=f"Source {source_code} is an {charter.collection_mode} source; manual capture is not permitted.",
        )

    clean_query = query_input.strip()
    if not clean_query:
        raise HTTPException(status_code=400, detail="Query input cannot be empty.")

    clean_outcome = outcome.strip().upper()
    if clean_outcome not in (s.value for s in SourceRunStatus):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid outcome {outcome!r}. Must be FOUND, NOT_FOUND, or FAILED.",
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    source_run = SourceRun(
        case_id=case.id,
        source_id=charter.id,
        operator_id=operator.id,
        query_input=clean_query,
        status=clean_outcome,
        started_at=now,
        completed_at=now,
    )
    db.add(source_run)
    db.flush()

    record = None
    if clean_outcome == SourceRunStatus.FOUND.value:
        if not title or not title.strip():
            raise HTTPException(status_code=400, detail="Record title is required for FOUND evidence.")
        if not source_url or not (source_url.startswith("http://") or source_url.startswith("https://")):
            raise HTTPException(
                status_code=400,
                detail="Valid source URL (http:// or https://) is required for FOUND evidence.",
            )
        if not raw_content or len(raw_content.strip()) < 20:
            raise HTTPException(
                status_code=400,
                detail="Raw content snapshot must be at least 20 characters.",
            )

        # Normalize line endings to LF before hashing
        normalized_content = raw_content.replace("\r\n", "\n").replace("\r", "\n")
        snapshot_hash = hashlib.sha256(normalized_content.encode("utf-8")).hexdigest().lower()

        record = Record(
            case_id=case.id,
            source_run_id=source_run.id,
            source_id=charter.id,
            title=title.strip(),
            source_url=source_url.strip(),
            raw_content=normalized_content,
            content_type=content_type or "text/plain",
            snapshot_hash=snapshot_hash,
            extractor_version="m2-v1.0",
            retrieved_at=now,
            triage_status=TriageStatus.PENDING_TRIAGE.value,
        )
        db.add(record)
        db.flush()

    log_action(
        db,
        action="source_run_manual",
        user_id=operator.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={
            "source_code": source_code,
            "query_input": clean_query,
            "status": clean_outcome,
            "source_run_id": source_run.id,
            "record_id": record.id if record else None,
            "snapshot_hash": record.snapshot_hash if record else None,
        },
        ip=ip,
    )
    db.commit()
    db.refresh(source_run)
    if record:
        db.refresh(record)
    return source_run, record


def triage_record(
    db: Session,
    case: Case,
    record_id: int,
    user: User,
    status: str,
    triage_note: Optional[str] = None,
    ip: Optional[str] = None,
) -> Record:
    """Triage a captured evidence record as ACCEPTED or REJECTED."""
    if case.stage != CaseStage.COLLECT.value:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot triage record: case is in stage {case.stage}, expected COLLECT.",
        )
    _check_operator_permission(case, user, "triage evidence records")

    clean_status = status.strip().upper()
    if clean_status not in (TriageStatus.ACCEPTED.value, TriageStatus.REJECTED.value):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid triage status {status!r}. Must be ACCEPTED or REJECTED.",
        )

    record = (
        db.query(Record)
        .filter(Record.id == record_id, Record.case_id == case.id)
        .first()
    )
    if not record:
        raise HTTPException(status_code=404, detail="Evidence record not found on this case.")

    clean_note = triage_note.strip() if triage_note else ""
    if clean_status == TriageStatus.REJECTED.value and len(clean_note) < 5:
        raise HTTPException(
            status_code=400,
            detail="A rejection reason of at least 5 characters is mandatory when rejecting a record.",
        )

    now = datetime.datetime.now(datetime.timezone.utc)
    record.triage_status = clean_status
    record.triage_note = clean_note or None
    record.triaged_by_id = user.id
    record.triaged_at = now

    log_action(
        db,
        action="record_triaged",
        user_id=user.id,
        case_id=case.id,
        from_stage=case.stage,
        to_stage=case.stage,
        allowed=True,
        detail={
            "record_id": record.id,
            "snapshot_hash": record.snapshot_hash,
            "triage_status": clean_status,
            "triage_note": record.triage_note,
        },
        ip=ip,
    )
    db.commit()
    db.refresh(record)
    return record


def get_case_collection_summary(db: Session, case_id: int) -> dict:
    """Return summary counts of source runs and record triage states for a case."""
    runs = db.query(SourceRun).filter(SourceRun.case_id == case_id).all()
    records = db.query(Record).filter(Record.case_id == case_id).all()

    total_runs = len(runs)
    total_records = len(records)
    pending_records = sum(1 for r in records if r.triage_status == TriageStatus.PENDING_TRIAGE.value)
    accepted_records = sum(1 for r in records if r.triage_status == TriageStatus.ACCEPTED.value)
    rejected_records = sum(1 for r in records if r.triage_status == TriageStatus.REJECTED.value)

    can_advance = (
        total_runs >= 1
        and pending_records == 0
        and (accepted_records >= 1)  # Or attested zero findings
    )

    return {
        "total_runs": total_runs,
        "total_records": total_records,
        "pending_records": pending_records,
        "accepted_records": accepted_records,
        "rejected_records": rejected_records,
        "can_advance_standard": can_advance,
        "requires_zero_findings_attestation": total_runs >= 1 and pending_records == 0 and accepted_records == 0,
    }
