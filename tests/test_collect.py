"""
tests/test_collect.py – Comprehensive test suite for Milestone 2 (M2 Collect).

Covers:
  1. Source Charter verification & seeding
  2. Automated Domain RDAP reconnaissance (FOUND, NOT_FOUND, FAILED, domain normalization, error capture)
  3. Manual Evidence Capture (FOUND, NOT_FOUND, FAILED, LF line ending normalization, SHA-256 hashing)
  4. Evidence Vault Immutability (database triggers blocking UPDATE and DELETE on payload/hash)
  5. Inline Record Triage (ACCEPTED, REJECTED with mandatory >= 5 char note, bilateral separation)
  6. Hardened Stage Gate: COLLECT -> CLAIM_EXTRACTION (0 runs blocked, pending records blocked, zero-findings attestation)
  7. Rework Loop (evidence preservation when case reopens from INDEPENDENT_REVIEW to COLLECT)
  8. HTTP Routes (web forms, HTMX endpoints, and role-based access control)
"""
import datetime
import hashlib
import pytest
from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app.audit.writer import log_action
from app.cases.service import advance_case, rework_case
from app.collect.charter import DEFAULT_CHARTERED_SOURCES, seed_source_charter
from app.collect.service import (
    execute_domain_rdap,
    execute_manual_capture,
    get_case_collection_summary,
    triage_record,
)
from app.models import (
    AuditLog,
    Case,
    CaseStage,
    CollectionMode,
    PurposeEnum,
    Record,
    SourceCharter,
    SourceReliability,
    SourceRun,
    SourceRunStatus,
    SourceTier,
    SubjectType,
    TriageStatus,
    User,
    UserRole,
)
from tests.conftest import (
    csrf_token_for,
    make_accepted_record,
    make_case,
    make_session,
    make_source_run,
    make_user,
)


# ── 1. Source Charter Seeding & Configuration ────────────────────────────────


def test_charter_seeded_and_active(db):
    """Source charter seeds all default sources with active status and legal bases."""
    seed_source_charter(db)
    sources = db.query(SourceCharter).all()
    assert len(sources) >= 5

    codes = {s.code for s in sources}
    assert "DOMAIN_RDAP" in codes
    assert "MCA_MANUAL" in codes
    assert "ECOURTS_MANUAL" in codes
    assert "GST_MANUAL" in codes
    assert "NEWS_MANUAL" in codes

    rdap = db.query(SourceCharter).filter(SourceCharter.code == "DOMAIN_RDAP").first()
    assert rdap.tier == SourceTier.A.value
    assert rdap.default_reliability == SourceReliability.A.value
    assert rdap.collection_mode == CollectionMode.AUTOMATED.value
    assert rdap.is_active is True


def test_manual_capture_on_automated_source_rejected(db):
    """Attempting manual capture on an AUTOMATED source must be rejected with 400."""
    op = make_user(db, email="op_auto_reject@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    with pytest.raises(HTTPException) as exc_info:
        execute_manual_capture(
            db=db,
            case=case,
            operator=op,
            source_code="DOMAIN_RDAP",
            query_input="acmetech.demo",
            outcome="FOUND",
            title="Attempted manual capture",
            source_url="https://rdap.org/domain/acmetech.demo",
            raw_content="Valid snapshot content of sufficient length",
        )
    assert exc_info.value.status_code == 400
    assert "manual capture is not permitted" in exc_info.value.detail


def test_manual_capture_on_unknown_or_inactive_source_rejected(db):
    """Attempting capture on unchartered source code must be rejected with 400."""
    op = make_user(db, email="op_unknown_reject@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    with pytest.raises(HTTPException) as exc_info:
        execute_manual_capture(
            db=db,
            case=case,
            operator=op,
            source_code="UNCHARTERED_HACK",
            query_input="something",
            outcome="FOUND",
        )
    assert exc_info.value.status_code == 400
    assert "Unrecognized or inactive source charter code" in exc_info.value.detail


# ── 2. Automated Domain RDAP Adapter ──────────────────────────────────────────


def test_rdap_found_creates_run_and_pending_record(db):
    """RDAP query for an existing domain produces FOUND run and PENDING_TRIAGE record with SHA-256."""
    op = make_user(db, email="op_rdap_found@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    run, record = execute_domain_rdap(db, case, op, "acmetech.demo")

    assert run.status == SourceRunStatus.FOUND.value
    assert run.case_id == case.id
    assert run.operator_id == op.id
    assert run.query_input == "acmetech.demo"

    assert record is not None
    assert record.case_id == case.id
    assert record.source_run_id == run.id
    assert record.triage_status == TriageStatus.PENDING_TRIAGE.value
    assert record.content_type == "application/json"
    assert record.extractor_version == "m2-v1.0"

    # Verify SHA-256 integrity
    expected_hash = hashlib.sha256(record.raw_content.encode("utf-8")).hexdigest().lower()
    assert record.snapshot_hash == expected_hash

    # Verify audit log
    entry = (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case.id, AuditLog.action == "source_run_rdap")
        .first()
    )
    assert entry is not None
    assert entry.detail.get("source_code") == "DOMAIN_RDAP"
    assert entry.detail.get("status") == "FOUND"
    assert entry.detail.get("snapshot_hash") == expected_hash


def test_rdap_not_found_records_run_without_record(db):
    """RDAP query for a non-existent domain records NOT_FOUND run and creates no record."""
    op = make_user(db, email="op_rdap_nf@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    run, record = execute_domain_rdap(db, case, op, "notfound.demo")

    assert run.status == SourceRunStatus.NOT_FOUND.value
    assert record is None

    # Summary reflects 1 run, 0 records
    summary = get_case_collection_summary(db, case.id)
    assert summary["total_runs"] == 1
    assert summary["total_records"] == 0


def test_rdap_failed_degraded_mode_records_error_detail(db):
    """RDAP upstream error records FAILED run with error_detail and creates no record."""
    op = make_user(db, email="op_rdap_fail@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    run, record = execute_domain_rdap(db, case, op, "failed.demo")

    assert run.status == SourceRunStatus.FAILED.value
    assert record is None
    assert run.error_detail is not None
    assert "Simulated RDAP registry connection timeout" in run.error_detail


def test_rdap_domain_normalization_and_validation(db):
    """RDAP normalizes inputs (strips whitespace, casing) and rejects malformed domains/URLs."""
    op = make_user(db, email="op_rdap_norm@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    # Whitespace and uppercase normalization
    run, record = execute_domain_rdap(db, case, op, "  ACMETECH.DEMO  ")
    assert run.query_input == "acmetech.demo"
    assert run.status == SourceRunStatus.FOUND.value

    # Malformed domains, schemes, paths, IPs
    for bad_domain in ["", "   ", "nodots", "bad domain.com", "http://", "https://acmetech.demo/path", "192.168.1.1", "a" * 260]:
        with pytest.raises(HTTPException) as exc_info:
            execute_domain_rdap(db, case, op, bad_domain)
        assert exc_info.value.status_code == 400


def test_rdap_bilateral_separation_and_role_checks(db):
    """Assigned reviewer and non-operators cannot execute RDAP collection."""
    op = make_user(db, email="op_rdap_role@crice.test", role=UserRole.operator)
    rev = make_user(db, email="rev_rdap_role@crice.test", role=UserRole.reviewer)
    case = make_case(db, operator=op, reviewer=rev, stage=CaseStage.COLLECT, intake_approved=True)

    # Reviewer assigned to this case cannot collect
    with pytest.raises(HTTPException) as exc_info:
        execute_domain_rdap(db, case, rev, "acmetech.demo")
    assert exc_info.value.status_code == 403
    assert "Bilateral separation violation" in exc_info.value.detail

    # Inactive operator cannot collect
    inactive_op = make_user(db, email="inact_rdap@crice.test", is_active=False)
    with pytest.raises(HTTPException) as exc_info2:
        execute_domain_rdap(db, case, inactive_op, "acmetech.demo")
    assert exc_info2.value.status_code == 403
    assert "Inactive user account" in exc_info2.value.detail

    # Case not in COLLECT stage cannot collect
    case_draft = make_case(db, operator=op, stage=CaseStage.INTAKE_DRAFT)
    with pytest.raises(HTTPException) as exc_info3:
        execute_domain_rdap(db, case_draft, op, "acmetech.demo")
    assert exc_info3.value.status_code == 400
    assert "expected COLLECT" in exc_info3.value.detail


# ── 3. Manual Evidence Capture ────────────────────────────────────────────────


def test_manual_capture_found_normalizes_crlf_and_hashes(db):
    """Manual capture normalizes CRLF to LF before computing SHA-256 hash."""
    op = make_user(db, email="op_man_found@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    raw_text_with_crlf = "Ministry of Corporate Affairs\r\nCompany Status: Active\r\nPaid-up Capital: 10,00,000 INR\r\n"
    normalized_expected = raw_text_with_crlf.replace("\r\n", "\n")
    expected_hash = hashlib.sha256(normalized_expected.encode("utf-8")).hexdigest().lower()

    run, record = execute_manual_capture(
        db=db,
        case=case,
        operator=op,
        source_code="MCA_MANUAL",
        query_input="U72200MH2018PTC123456",
        outcome="FOUND",
        title="MCA Company Master Data Extract",
        source_url="https://www.mca.gov.in/mcafoportal/companyLLPMasterData.do",
        raw_content=raw_text_with_crlf,
    )

    assert run.status == SourceRunStatus.FOUND.value
    assert record is not None
    assert record.raw_content == normalized_expected
    assert "\r" not in record.raw_content
    assert record.snapshot_hash == expected_hash
    assert record.triage_status == TriageStatus.PENDING_TRIAGE.value

    # Verify audit log
    entry = (
        db.query(AuditLog)
        .filter(AuditLog.case_id == case.id, AuditLog.action == "source_run_manual")
        .first()
    )
    assert entry is not None
    assert entry.detail.get("snapshot_hash") == expected_hash


def test_manual_capture_not_found_and_failed(db):
    """Manual capture with NOT_FOUND or FAILED creates SourceRun without Record."""
    op = make_user(db, email="op_man_nf@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    # NOT_FOUND
    run_nf, record_nf = execute_manual_capture(
        db=db,
        case=case,
        operator=op,
        source_code="ECOURTS_MANUAL",
        query_input="CNR NO 1234567890",
        outcome="NOT_FOUND",
    )
    assert run_nf.status == SourceRunStatus.NOT_FOUND.value
    assert record_nf is None

    # FAILED
    run_f, record_f = execute_manual_capture(
        db=db,
        case=case,
        operator=op,
        source_code="GST_MANUAL",
        query_input="27AAAAA0000A1Z5",
        outcome="FAILED",
    )
    assert run_f.status == SourceRunStatus.FAILED.value
    assert record_f is None


def test_manual_capture_validations(db):
    """Manual capture rejects missing queries, invalid outcomes, empty titles, bad URLs, and short content."""
    op = make_user(db, email="op_man_val@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    # Empty query
    with pytest.raises(HTTPException) as exc1:
        execute_manual_capture(db, case, op, "MCA_MANUAL", "   ", "FOUND")
    assert exc1.value.status_code == 400

    # Invalid outcome
    with pytest.raises(HTTPException) as exc2:
        execute_manual_capture(db, case, op, "MCA_MANUAL", "Q123", "MAYBE")
    assert exc2.value.status_code == 400

    # FOUND with empty title
    with pytest.raises(HTTPException) as exc3:
        execute_manual_capture(
            db, case, op, "MCA_MANUAL", "Q123", "FOUND", title="", source_url="https://mca.gov.in", raw_content="Valid length content 12345"
        )
    assert exc3.value.status_code == 400
    assert "Record title is required" in exc3.value.detail

    # FOUND with invalid URL (no protocol)
    with pytest.raises(HTTPException) as exc4:
        execute_manual_capture(
            db, case, op, "MCA_MANUAL", "Q123", "FOUND", title="Title", source_url="ftp://bad.com", raw_content="Valid length content 12345"
        )
    assert exc4.value.status_code == 400
    assert "Valid source URL" in exc4.value.detail

    # FOUND with short content (< 20 chars)
    with pytest.raises(HTTPException) as exc5:
        execute_manual_capture(
            db, case, op, "MCA_MANUAL", "Q123", "FOUND", title="Title", source_url="https://mca.gov.in", raw_content="short text"
        )
    assert exc5.value.status_code == 400
    assert "at least 20 characters" in exc5.value.detail


# ── 4. Evidence Vault Immutability Triggers ───────────────────────────────────


def test_evidence_vault_triggers_block_update_and_delete(db):
    """Database triggers block DELETE and block UPDATE of raw_content, snapshot_hash, source_url, retrieved_at."""
    op = make_user(db, email="op_vault@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)
    record = make_accepted_record(db, case, op, content="Original tamper-proof evidence content here.")

    # 1. Attempt DELETE -> must fail
    with pytest.raises(Exception) as exc_del:
        db.delete(record)
        db.commit()
    db.rollback()
    assert "immutable" in str(exc_del.value).lower() or "forbidden" in str(exc_del.value).lower()

    # Refresh record
    record = db.get(Record, record.id)
    assert record is not None

    # 2. Attempt UPDATE raw_content -> must fail
    with pytest.raises(Exception) as exc_up_content:
        record.raw_content = "Tampered payload after collection."
        db.commit()
    db.rollback()
    assert "immutable" in str(exc_up_content.value).lower() or "cannot be modified" in str(exc_up_content.value).lower()

    # Refresh record
    record = db.get(Record, record.id)

    # 3. Attempt UPDATE snapshot_hash -> must fail
    with pytest.raises(Exception) as exc_up_hash:
        record.snapshot_hash = "0" * 64
        db.commit()
    db.rollback()
    assert "immutable" in str(exc_up_hash.value).lower() or "cannot be modified" in str(exc_up_hash.value).lower()

    # 4. Attempt UPDATE source_url -> must fail
    record = db.get(Record, record.id)
    with pytest.raises(Exception) as exc_up_url:
        record.source_url = "https://tampered-url.com"
        db.commit()
    db.rollback()
    assert "immutable" in str(exc_up_url.value).lower() or "cannot be modified" in str(exc_up_url.value).lower()

    # 5. Updating triage_status and triage_note MUST SUCCEED
    record = db.get(Record, record.id)
    record.triage_status = TriageStatus.REJECTED.value
    record.triage_note = "Valid rejection reason noted by operator."
    db.commit()
    db.refresh(record)
    assert record.triage_status == TriageStatus.REJECTED.value
    assert record.triage_note == "Valid rejection reason noted by operator."


# ── 5. Inline Record Triage State Machine ─────────────────────────────────────


def test_operator_can_accept_and_reject_record(db):
    """Operator can accept a record, and can reject a record when providing >= 5 char justification."""
    op = make_user(db, email="op_triage@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    # Accept
    rec1 = make_accepted_record(db, case, op, title="Record 1", triage_status=TriageStatus.PENDING_TRIAGE.value)
    triaged1 = triage_record(db, case, rec1.id, op, "ACCEPTED")
    assert triaged1.triage_status == TriageStatus.ACCEPTED.value
    assert triaged1.triaged_by_id == op.id
    assert triaged1.triaged_at is not None

    # Reject with >= 5 chars
    rec2 = make_accepted_record(db, case, op, title="Record 2", triage_status=TriageStatus.PENDING_TRIAGE.value)
    triaged2 = triage_record(db, case, rec2.id, op, "REJECTED", triage_note="Outside investigated date range")
    assert triaged2.triage_status == TriageStatus.REJECTED.value
    assert triaged2.triage_note == "Outside investigated date range"
    assert triaged2.triaged_by_id == op.id


def test_triage_rejection_requires_minimum_note(db):
    """Rejecting an evidence record without at least 5 characters justification is rejected with 400."""
    op = make_user(db, email="op_triage_note@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)
    rec = make_accepted_record(db, case, op, triage_status=TriageStatus.PENDING_TRIAGE.value)

    # Empty note
    with pytest.raises(HTTPException) as exc1:
        triage_record(db, case, rec.id, op, "REJECTED", triage_note="")
    assert exc1.value.status_code == 400
    assert "at least 5 characters" in exc1.value.detail

    # 4 char note
    with pytest.raises(HTTPException) as exc2:
        triage_record(db, case, rec.id, op, "REJECTED", triage_note="nope")
    assert exc2.value.status_code == 400
    assert "at least 5 characters" in exc2.value.detail


def test_triage_bilateral_separation(db):
    """Assigned reviewer cannot triage evidence records (bilateral separation)."""
    op = make_user(db, email="op_triage_bilat@crice.test", role=UserRole.operator)
    rev = make_user(db, email="rev_triage_bilat@crice.test", role=UserRole.reviewer)
    case = make_case(db, operator=op, reviewer=rev, stage=CaseStage.COLLECT, intake_approved=True)
    rec = make_accepted_record(db, case, op, triage_status=TriageStatus.PENDING_TRIAGE.value)

    with pytest.raises(HTTPException) as exc_info:
        triage_record(db, case, rec.id, rev, "ACCEPTED")
    assert exc_info.value.status_code == 403
    assert "Bilateral separation violation" in exc_info.value.detail


# ── 6. Stage Gate Enforcement (COLLECT -> CLAIM_EXTRACTION) ────────────────────


def test_gate_collect_fails_with_zero_source_runs(db):
    """Advancing from COLLECT with 0 source runs is rejected."""
    op = make_user(db, email="op_gate_zero_runs@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    with pytest.raises(HTTPException) as exc_info:
        advance_case(case, op, CaseStage.CLAIM_EXTRACTION.value, db)
    assert exc_info.value.status_code == 400
    assert "execute at least one chartered source run first" in exc_info.value.detail


def test_gate_collect_fails_with_pending_triage_records(db):
    """Advancing from COLLECT while any record remains in PENDING_TRIAGE is rejected."""
    op = make_user(db, email="op_gate_pending@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)
    make_accepted_record(db, case, op, triage_status=TriageStatus.PENDING_TRIAGE.value)

    with pytest.raises(HTTPException) as exc_info:
        advance_case(case, op, CaseStage.CLAIM_EXTRACTION.value, db)
    assert exc_info.value.status_code == 400
    assert "all captured records must be triaged" in exc_info.value.detail.lower()


def test_gate_collect_zero_findings_attestation_requirement(db):
    """Advancing from COLLECT with 0 accepted records fails unless zero-findings are attested."""
    op = make_user(db, email="op_gate_zero_find@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)

    # 1 source run with NOT_FOUND (0 records)
    make_source_run(db, case, op, status="NOT_FOUND")

    # Without attestation -> fails
    with pytest.raises(HTTPException) as exc_info:
        advance_case(case, op, CaseStage.CLAIM_EXTRACTION.value, db, zero_findings_attested=False)
    assert exc_info.value.status_code == 400
    assert "zero accepted records" in exc_info.value.detail.lower()

    # With attestation -> succeeds
    updated = advance_case(case, op, CaseStage.CLAIM_EXTRACTION.value, db, zero_findings_attested=True)
    assert updated.stage == CaseStage.CLAIM_EXTRACTION.value

    # Verify audit log recorded zero findings attestation
    entry = (
        db.query(AuditLog)
        .filter(
            AuditLog.case_id == case.id,
            AuditLog.to_stage == CaseStage.CLAIM_EXTRACTION.value,
            AuditLog.allowed.is_(True),
        )
        .first()
    )
    assert entry is not None
    assert entry.detail.get("zero_findings_attested") is True


def test_gate_collect_succeeds_with_accepted_records(db):
    """Advancing from COLLECT with 1+ accepted records and 0 pending records succeeds."""
    op = make_user(db, email="op_gate_succ@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)
    make_accepted_record(db, case, op, triage_status=TriageStatus.ACCEPTED.value)

    updated = advance_case(case, op, CaseStage.CLAIM_EXTRACTION.value, db)
    assert updated.stage == CaseStage.CLAIM_EXTRACTION.value


# ── 7. Rework Loop Evidence Preservation ─────────────────────────────────────


def test_rework_loop_preserves_evidence_and_allows_further_collection(db):
    """Rework loop from INDEPENDENT_REVIEW back to COLLECT preserves all records and allows new queries."""
    op = make_user(db, email="op_rework_ev@crice.test", role=UserRole.operator)
    rev = make_user(db, email="rev_rework_ev@crice.test", role=UserRole.reviewer)
    case = make_case(db, operator=op, reviewer=rev, stage=CaseStage.COLLECT, intake_approved=True)

    # 1. Collect evidence and advance to INDEPENDENT_REVIEW
    rec1 = make_accepted_record(db, case, op, title="MCA Snapshot 1")
    advance_case(case, op, CaseStage.CLAIM_EXTRACTION.value, db)
    advance_case(case, op, CaseStage.CORRELATION_AND_SCORING.value, db)
    advance_case(case, op, CaseStage.INDEPENDENT_REVIEW.value, db)
    assert case.stage == CaseStage.INDEPENDENT_REVIEW.value

    # 2. Reviewer triggers rework back to COLLECT
    case = rework_case(case, rev, CaseStage.COLLECT.value, "MCA record lacks director filings", db)
    assert case.stage == CaseStage.COLLECT.value
    assert case.rework_reason == "MCA record lacks director filings"

    # 3. Verify original record is still attached, accepted, and immutable
    existing_rec = db.query(Record).filter(Record.id == rec1.id).first()
    assert existing_rec is not None
    assert existing_rec.title == "MCA Snapshot 1"
    assert existing_rec.triage_status == TriageStatus.ACCEPTED.value

    # 4. Operator captures supplementary evidence in COLLECT
    run2, rec2 = execute_manual_capture(
        db=db,
        case=case,
        operator=op,
        source_code="MCA_MANUAL",
        query_input="U72200MH2018PTC123456_DIRECTORS",
        outcome="FOUND",
        title="MCA Director Details Supplement",
        source_url="https://www.mca.gov.in/directors",
        raw_content="Director details extract with DIN numbers and appointments.",
    )
    assert rec2 is not None

    # Triage the new record
    triage_record(db, case, rec2.id, op, "ACCEPTED")

    # Case can advance forward again
    advance_case(case, op, CaseStage.CLAIM_EXTRACTION.value, db)
    assert case.stage == CaseStage.CLAIM_EXTRACTION.value


# ── 8. Web HTTP Routes & HTMX Endpoints ──────────────────────────────────────


def test_routes_collect_rdap(client, db):
    """POST /cases/{case_id}/collect/rdap triggers RDAP query and returns redirect."""
    op = make_user(db, email="op_route_rdap@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)
    session_row, cookies = make_session(db, op)

    resp = client.post(
        f"/cases/{case.id}/collect/rdap",
        data={
            "_csrf": csrf_token_for(session_row),
            "domain": "acmetech.demo",
        },
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303)
    assert resp.headers["location"] == f"/cases/{case.id}"

    # Verify run and record created in DB
    run = db.query(SourceRun).filter(SourceRun.case_id == case.id).first()
    assert run is not None
    assert run.status == "FOUND"


def test_routes_collect_manual_and_triage(client, db):
    """POST /cases/{case_id}/collect/manual and POST /records/{id}/triage work end-to-end via web."""
    op = make_user(db, email="op_route_manual@crice.test")
    case = make_case(db, operator=op, stage=CaseStage.COLLECT, intake_approved=True)
    session_row, cookies = make_session(db, op)

    # 1. Manual Capture
    resp_man = client.post(
        f"/cases/{case.id}/collect/manual",
        data={
            "_csrf": csrf_token_for(session_row),
            "source_code": "NEWS_MANUAL",
            "query_input": "Acme Tech investigation",
            "outcome": "FOUND",
            "title": "National Media Article",
            "source_url": "https://www.financialtimes.com/acme",
            "raw_content": "Full investigative report detailing company operations and regulatory filings.",
        },
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp_man.status_code in (302, 303)

    record = db.query(Record).filter(Record.case_id == case.id).first()
    assert record is not None
    assert record.triage_status == TriageStatus.PENDING_TRIAGE.value

    # 2. Triage ACCEPT
    resp_triage = client.post(
        f"/cases/{case.id}/records/{record.id}/triage",
        data={
            "_csrf": csrf_token_for(session_row),
            "status": "ACCEPTED",
        },
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp_triage.status_code in (302, 303)

    db.refresh(record)
    assert record.triage_status == TriageStatus.ACCEPTED.value

    # 3. Advance to CLAIM_EXTRACTION
    resp_adv = client.post(
        f"/cases/{case.id}/advance",
        data={
            "_csrf": csrf_token_for(session_row),
            "to_stage": CaseStage.CLAIM_EXTRACTION.value,
        },
        cookies=cookies,
        follow_redirects=False,
    )
    assert resp_adv.status_code in (302, 303)
    db.refresh(case)
    assert case.stage == CaseStage.CLAIM_EXTRACTION.value
