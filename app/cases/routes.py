"""
app/cases/routes.py – HTTP routes and HTMX endpoints for the CRICE Case DAG workflow.
Enforces:
  - Single primary action per stage view.
  - Role-gated controls with clear explanatory status banners.
  - Forward advance, backward rework, consent verification, and post-release recall.
  - Total audit logging via cases/service.py.
"""
from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

from app.auth.roles import get_current_user
from app.cases.service import (
    ALLOWED_TRANSITIONS,
    VERIFIED_B2B_CLIENTS,
    advance_case,
    approve_intake,
    assign_reviewer,
    create_case,
    recall_case,
    rework_case,
    verify_client_kyc,
    verify_consent,
)
from app.collect.service import (
    execute_domain_rdap,
    execute_manual_capture,
    get_case_collection_summary,
    triage_record,
)
from app.db import get_db
from app.models import (
    AuditLog,
    Case,
    CaseStage,
    CollectionMode,
    PurposeEnum,
    Record,
    SourceCharter,
    SourceRun,
    STAGE_ORDER,
    Session as SessionModel,
    SubjectType,
    TriageStatus,
    User,
    UserRole,
)
from app.templates_config import templates

router = APIRouter(tags=["cases"])


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _get_sess(request: Request, db: Session) -> Optional[SessionModel]:
    from app.auth.sessions import load_session
    sid = getattr(request.state, "session_id", None)
    return load_session(db, sid)


def _csrf_ok(request: Request, submitted: str, db: Session) -> bool:
    sess = _get_sess(request, db)
    return bool(sess and submitted == sess.csrf_token)


# ── GET /cases ────────────────────────────────────────────────────────────────


@router.get("/cases", response_model=None)
def cases_list(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    sess = _get_sess(request, db)
    if current_user.role == UserRole.compliance_admin.value:
        cases = db.query(Case).order_by(Case.created_at.desc()).all()
    else:
        cases = (
            db.query(Case)
            .filter(
                (Case.operator_id == current_user.id)
                | (Case.reviewer_id == current_user.id)
            )
            .order_by(Case.created_at.desc())
            .all()
        )
    return templates.TemplateResponse(
        request,
        "cases/list.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": sess.csrf_token if sess else "",
            "cases": cases,
            "STAGE_ORDER": STAGE_ORDER,
        },
    )


# ── GET /cases/new ────────────────────────────────────────────────────────────


@router.get("/cases/new", response_model=None)
def cases_new_get(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    sess = _get_sess(request, db)
    return templates.TemplateResponse(
        request,
        "cases/new.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": sess.csrf_token if sess else "",
            "purposes": list(PurposeEnum),
            "subject_types": list(SubjectType),
            "verified_clients": list(VERIFIED_B2B_CLIENTS.keys()),
            "error": None,
        },
    )


# ── POST /cases/new ───────────────────────────────────────────────────────────


@router.post("/cases/new", response_model=None)
async def cases_new_post(
    request: Request,
    client_name: str = Form(...),
    purpose: str = Form(...),
    subject_type: str = Form(...),
    subject_name: str = Form(...),
    subject_identifier: str = Form(default=""),
    client_kyc_verified: bool = Form(default=False),
    msa_signed: bool = Form(default=False),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    sess = _get_sess(request, db)

    if not _csrf_ok(request, csrf_token, db):
        return templates.TemplateResponse(
            request,
            "cases/new.html",
            {
                "request": request,
                "current_user": current_user,
                "csrf_token": sess.csrf_token if sess else "",
                "purposes": list(PurposeEnum),
                "subject_types": list(SubjectType),
                "error": "Security check failed. Please try again.",
            },
            status_code=403,
        )

    try:
        case = create_case(
            db=db,
            acting_user=current_user,
            client_name=client_name.strip(),
            purpose=purpose,
            subject_type=subject_type,
            subject_name=subject_name.strip(),
            subject_identifier=subject_identifier.strip() or None,
            client_kyc_verified=client_kyc_verified,
            msa_signed=msa_signed,
            ip=_ip(request),
        )
    except HTTPException as exc:
        return templates.TemplateResponse(
            request,
            "cases/new.html",
            {
                "request": request,
                "current_user": current_user,
                "csrf_token": sess.csrf_token if sess else "",
                "purposes": list(PurposeEnum),
                "subject_types": list(SubjectType),
                "error": exc.detail,
            },
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case.id}", status_code=302)


# ── GET /cases/{id} ───────────────────────────────────────────────────────────


@router.get("/cases/{case_id}", response_model=None)
def case_workspace(
    case_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    # Access control: compliance_admin, assigned operator, or assigned reviewer
    if (
        current_user.role != UserRole.compliance_admin.value
        and case.operator_id != current_user.id
        and case.reviewer_id != current_user.id
    ):
        raise HTTPException(status_code=403, detail="Access denied to this case.")

    sess = _get_sess(request, db)

    # Determine forward stage target
    forward_target = None
    allowed_targets = ALLOWED_TRANSITIONS.get(case.stage, [])
    # Forward targets in standard progression
    forward_progression = {
        CaseStage.INTAKE_DRAFT.value: CaseStage.COMPLIANCE_GATE.value,
        CaseStage.COMPLIANCE_GATE.value: CaseStage.COLLECT.value,
        CaseStage.COLLECT.value: CaseStage.CLAIM_EXTRACTION.value,
        CaseStage.CLAIM_EXTRACTION.value: CaseStage.CORRELATION_AND_SCORING.value,
        CaseStage.CORRELATION_AND_SCORING.value: CaseStage.INDEPENDENT_REVIEW.value,
        CaseStage.INDEPENDENT_REVIEW.value: CaseStage.BUILD_AND_QA.value,
        CaseStage.BUILD_AND_QA.value: CaseStage.RELEASE_GATE.value,
        CaseStage.RELEASE_GATE.value: CaseStage.CLOSED.value,
    }
    forward_target = forward_progression.get(case.stage)

    # Eligible reviewers list for assignment (compliance_admin only)
    reviewers = []
    if current_user.role == UserRole.compliance_admin.value:
        reviewers = (
            db.query(User)
            .filter(
                User.role == UserRole.reviewer.value,
                User.is_active.is_(True),
                User.id != case.operator_id,  # Exclude operator
            )
            .all()
        )

    # Recent audit feed
    feed = (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(25)
        .all()
    )

    # Source runs, records, and chartered sources for M2
    source_runs = (
        db.query(SourceRun)
        .filter(SourceRun.case_id == case_id)
        .order_by(SourceRun.started_at.desc())
        .all()
    )
    records = (
        db.query(Record)
        .filter(Record.case_id == case_id)
        .order_by(Record.retrieved_at.desc())
        .all()
    )
    chartered_sources = (
        db.query(SourceCharter)
        .filter(SourceCharter.is_active.is_(True))
        .order_by(SourceCharter.code)
        .all()
    )
    collection_summary = get_case_collection_summary(db, case_id)

    # Determine role-specific action authorization
    is_operator = case.operator_id == current_user.id
    is_reviewer = case.reviewer_id == current_user.id
    is_admin = current_user.role == UserRole.compliance_admin.value

    can_advance = False
    advance_block_reason = None

    if case.stage == CaseStage.INTAKE_DRAFT.value:
        can_advance = is_operator or is_admin
    elif case.stage == CaseStage.COMPLIANCE_GATE.value:
        can_advance = is_admin
        if not is_admin:
            advance_block_reason = "Awaiting Compliance Administrator intake approval."
        elif case.purpose == PurposeEnum.employee_screening_with_consent.value and not case.consent_verified:
            advance_block_reason = "Employee screening requires verified consent before approval."
    elif case.stage == CaseStage.COLLECT.value:
        role_allowed = is_operator or is_admin
        if not role_allowed:
            advance_block_reason = "Collection is managed by the assigned operator."
            can_advance = False
        else:
            if collection_summary["total_runs"] == 0:
                can_advance = False
                advance_block_reason = "Cannot advance: execute at least one chartered source run first."
            elif collection_summary["pending_records"] > 0:
                can_advance = False
                advance_block_reason = f"Cannot advance: {collection_summary['pending_records']} record(s) pending triage. All captured records must be ACCEPTED or REJECTED."
            elif collection_summary["accepted_records"] == 0:
                can_advance = False
                advance_block_reason = "Zero accepted records. Attest to Zero Findings to advance."
            else:
                can_advance = True
    elif case.stage == CaseStage.CLAIM_EXTRACTION.value:
        can_advance = is_operator or is_admin
        if not can_advance:
            advance_block_reason = "Extraction is managed by the assigned operator."
    elif case.stage == CaseStage.CORRELATION_AND_SCORING.value:
        can_advance = is_operator or is_admin
        if not case.reviewer_id:
            advance_block_reason = "A reviewer must be assigned by Compliance Administrator before entering Independent Review."
    elif case.stage == CaseStage.INDEPENDENT_REVIEW.value:
        can_advance = is_reviewer
        if not is_reviewer:
            advance_block_reason = f"Locked for Independent Review by {case.reviewer.full_name if case.reviewer else 'assigned reviewer'}."
    elif case.stage == CaseStage.BUILD_AND_QA.value:
        can_advance = is_operator or is_admin
    elif case.stage == CaseStage.RELEASE_GATE.value:
        can_advance = is_admin
        if not is_admin:
            advance_block_reason = "Awaiting executive release sign-off by Compliance Administrator."
    elif case.stage == CaseStage.CLOSED.value:
        can_advance = False

    return templates.TemplateResponse(
        request,
        "cases/workspace.html",
        {
            "request": request,
            "current_user": current_user,
            "csrf_token": sess.csrf_token if sess else "",
            "case": case,
            "forward_target": forward_target,
            "can_advance": can_advance,
            "advance_block_reason": advance_block_reason,
            "is_operator": is_operator,
            "is_reviewer": is_reviewer,
            "is_admin": is_admin,
            "reviewers": reviewers,
            "feed": feed,
            "source_runs": source_runs,
            "records": records,
            "chartered_sources": chartered_sources,
            "collection_summary": collection_summary,
            "STAGE_ORDER": STAGE_ORDER,
            "CaseStage": CaseStage,
            "UserRole": UserRole,
            "PurposeEnum": PurposeEnum,
            "TriageStatus": TriageStatus,
        },
    )


# ── POST /cases/{id}/advance ──────────────────────────────────────────────────


@router.post("/cases/{case_id}/advance", response_model=None)
async def case_advance_post(
    case_id: int,
    request: Request,
    to_stage: str = Form(...),
    zero_findings_attested: bool = Form(default=False),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not _csrf_ok(request, csrf_token, db):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    try:
        advance_case(
            case,
            current_user,
            to_stage,
            db,
            ip=_ip(request),
            zero_findings_attested=zero_findings_attested,
        )
    except HTTPException as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">{exc.detail}</div>',
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case.id}", status_code=302)


# ── POST /cases/{id}/rework ───────────────────────────────────────────────────


@router.post("/cases/{case_id}/rework", response_model=None)
async def case_rework_post(
    case_id: int,
    request: Request,
    to_stage: str = Form(...),
    rework_reason: str = Form(...),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not _csrf_ok(request, csrf_token, db):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    try:
        rework_case(case, current_user, to_stage, rework_reason, db, ip=_ip(request))
    except HTTPException as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">{exc.detail}</div>',
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case_id}", status_code=302)


# ── POST /cases/{id}/recall ───────────────────────────────────────────────────


@router.post("/cases/{case_id}/recall", response_model=None)
async def case_recall_post(
    case_id: int,
    request: Request,
    recall_reason: str = Form(...),
    reopen_to_stage: str = Form(...),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not _csrf_ok(request, csrf_token, db):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    try:
        recall_case(case, current_user, recall_reason, reopen_to_stage, db, ip=_ip(request))
    except HTTPException as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">{exc.detail}</div>',
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case_id}", status_code=302)


# ── POST /cases/{id}/verify_consent ───────────────────────────────────────────


@router.post("/cases/{case_id}/verify_consent", response_model=None)
async def case_verify_consent_post(
    case_id: int,
    request: Request,
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not _csrf_ok(request, csrf_token, db):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    try:
        verify_consent(case, current_user, db, ip=_ip(request))
    except HTTPException as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">{exc.detail}</div>',
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case_id}", status_code=302)


# ── POST /cases/{id}/verify_client ───────────────────────────────────────────


@router.post("/cases/{case_id}/verify_client", response_model=None)
async def case_verify_client_post(
    case_id: int,
    request: Request,
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not _csrf_ok(request, csrf_token, db):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    try:
        verify_client_kyc(case, current_user, db, ip=_ip(request))
    except HTTPException as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">{exc.detail}</div>',
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case_id}", status_code=302)


# ── POST /cases/{id}/approve_intake ──────────────────────────────────────────


@router.post("/cases/{case_id}/approve_intake", response_model=None)
async def case_approve_intake_post(
    case_id: int,
    request: Request,
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not _csrf_ok(request, csrf_token, db):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    try:
        approve_intake(case, current_user, db, ip=_ip(request))
    except HTTPException as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">{exc.detail}</div>',
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case_id}", status_code=302)


# ── POST /cases/{id}/assign_reviewer ─────────────────────────────────────────


@router.post("/cases/{case_id}/assign_reviewer", response_model=None)
async def case_assign_reviewer_post(
    case_id: int,
    request: Request,
    reviewer_id: int = Form(...),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not _csrf_ok(request, csrf_token, db):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    try:
        assign_reviewer(case, current_user, reviewer_id, db, ip=_ip(request))
    except HTTPException as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">{exc.detail}</div>',
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case_id}", status_code=302)


# ── GET /cases/{id}/feed ──────────────────────────────────────────────────────


@router.get("/cases/{case_id}/feed", response_model=None)
def case_feed_get(
    case_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> HTMLResponse:
    feed = (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case_id)
        .order_by(AuditLog.timestamp.desc())
        .limit(25)
        .all()
    )
    return templates.TemplateResponse(
        request,
        "cases/_feed.html",
        {
            "request": request,
            "feed": feed,
        },
    )


# ── POST /cases/{id}/collect/rdap ─────────────────────────────────────────────


@router.post("/cases/{case_id}/collect/rdap", response_model=None)
async def case_collect_rdap_post(
    case_id: int,
    request: Request,
    domain: str = Form(...),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not _csrf_ok(request, csrf_token, db):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    try:
        execute_domain_rdap(db, case, current_user, domain, ip=_ip(request))
    except HTTPException as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">{exc.detail}</div>',
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case_id}", status_code=302)


# ── POST /cases/{id}/collect/manual ───────────────────────────────────────────


@router.post("/cases/{case_id}/collect/manual", response_model=None)
async def case_collect_manual_post(
    case_id: int,
    request: Request,
    source_code: str = Form(...),
    query_input: str = Form(...),
    outcome: str = Form(...),
    title: Optional[str] = Form(default=None),
    source_url: Optional[str] = Form(default=None),
    raw_content: Optional[str] = Form(default=None),
    content_type: str = Form(default="text/plain"),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not _csrf_ok(request, csrf_token, db):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    try:
        execute_manual_capture(
            db=db,
            case=case,
            operator=current_user,
            source_code=source_code,
            query_input=query_input,
            outcome=outcome,
            title=title,
            source_url=source_url,
            raw_content=raw_content,
            content_type=content_type,
            ip=_ip(request),
        )
    except HTTPException as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">{exc.detail}</div>',
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case_id}", status_code=302)


# ── POST /cases/{id}/records/{record_id}/triage ───────────────────────────────


@router.post("/cases/{case_id}/records/{record_id}/triage", response_model=None)
async def case_record_triage_post(
    case_id: int,
    record_id: int,
    request: Request,
    status: str = Form(...),
    triage_note: Optional[str] = Form(default=None),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    if not _csrf_ok(request, csrf_token, db):
        raise HTTPException(status_code=403, detail="CSRF check failed.")

    case: Optional[Case] = db.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    try:
        triage_record(
            db=db,
            case=case,
            record_id=record_id,
            user=current_user,
            status=status,
            triage_note=triage_note,
            ip=_ip(request),
        )
    except HTTPException as exc:
        return HTMLResponse(
            f'<div class="alert alert-error">{exc.detail}</div>',
            status_code=exc.status_code,
        )

    return RedirectResponse(f"/cases/{case_id}", status_code=302)
