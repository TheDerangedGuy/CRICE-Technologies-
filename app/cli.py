"""
app/cli.py – management CLI.

Commands:
  create-admin   Create the first compliance_admin user.
  seed-demo      Create demo operator, reviewer, admin accounts and demo cases for local development.

Usage (from repo root):
  python -m app.cli create-admin
  python -m app.cli seed-demo
"""
import hashlib
import json
import secrets
import sys
import os

import datetime
from datetime import timezone
import hashlib
import json
import os
import secrets
import sys

import pyotp
from sqlalchemy.orm import sessionmaker
import typer

from app.audit.writer import log_action
from app.auth.password import _MIN_LENGTH, hash_password
from app.auth.totp_crypto import encrypt_totp_secret
from app.collect.charter import seed_source_charter
from app.db import Base, _get_engine
from app.dossier.service import compile_dossier
from app.models import (
    AdverseCategory,
    Case,
    CaseStage,
    Claim,
    Dossier,
    ExtractionMethod,
    MatchTier,
    PurposeEnum,
    Record,
    ReviewStatus,
    SourceCharter,
    SourceRun,
    SourceRunStatus,
    SubjectType,
    TriageStatus,
    User,
    UserRole,
)

app_cli = typer.Typer(name="crice", help="CRICE Lab management CLI")


def _get_db():
    factory = sessionmaker(bind=_get_engine())
    return factory()


def _generate_case_ref(db) -> str:
    for _ in range(20):
        ref = f"CRICE-{secrets.token_hex(4).upper()}"
        if not db.query(Case).filter(Case.case_ref == ref).first():
            return ref
    raise RuntimeError("Could not generate a unique case_ref")


@app_cli.command()
def create_admin(
    email: str = typer.Option(..., prompt=True, help="Admin email address"),
    full_name: str = typer.Option(..., prompt=True, help="Admin full name"),
    password: str = typer.Option(
        ...,
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help=f"Password (min {_MIN_LENGTH} characters)",
    ),
):
    """Create the first compliance_admin account."""
    if len(password) < _MIN_LENGTH:
        typer.echo(f"Error: password must be at least {_MIN_LENGTH} characters.", err=True)
        raise typer.Exit(1)

    db = _get_db()
    try:
        existing = db.query(User).filter(User.email == email.strip().lower()).first()
        if existing:
            typer.echo(f"Error: user with email {email!r} already exists.", err=True)
            raise typer.Exit(1)

        user = User(
            email=email.strip().lower(),
            full_name=full_name,
            password_hash=hash_password(password),
            role=UserRole.compliance_admin.value,
            mfa_enabled=False,
            is_active=True,
        )
        db.add(user)
        db.commit()
        typer.echo(f"✓ compliance_admin created: {user.email} (id={user.id})")
        typer.echo("  Log in and complete MFA setup on first login.")
    finally:
        db.close()


@app_cli.command()
def seed_demo():
    """Create demo accounts and initial demo cases for local development (idempotent)."""
    db = _get_db()
    password = "Demo1234!Demo"

    demos = [
        dict(email="operator@crice.demo", full_name="Demo Operator", role=UserRole.operator.value),
        dict(email="reviewer@crice.demo", full_name="Demo Reviewer", role=UserRole.reviewer.value),
        dict(email="admin@crice.demo", full_name="Demo Admin", role=UserRole.compliance_admin.value),
    ]

    try:
        users = {}
        for d in demos:
            existing = db.query(User).filter(User.email == d["email"]).first()
            if not existing:
                totp_secret = pyotp.random_base32()
                user = User(
                    **d,
                    password_hash=hash_password(password),
                    totp_secret_enc=encrypt_totp_secret(totp_secret),
                    mfa_enabled=True,
                    is_active=True,
                )
                db.add(user)
                db.flush()
                uri = pyotp.TOTP(totp_secret).provisioning_uri(
                    name=d["email"], issuer_name="CRICE Lab"
                )
                typer.echo(f"✓ Created {d['role']}: {d['email']}")
                typer.echo(f"  TOTP URI: {uri}")
                users[d["role"]] = user
            else:
                typer.echo(f"  Skip user (exists): {d['email']}")
                users[d["role"]] = existing

        db.commit()

        # Seed Source Charter
        charter_sources = seed_source_charter(db)
        charter_map = {s.code: s for s in charter_sources}
        typer.echo(f"✓ Seeded Source Charter ({len(charter_sources)} sources).")

        op_user = users.get(UserRole.operator.value)
        rev_user = users.get(UserRole.reviewer.value)

        # ── 1. Demo Case 1: Acme Technologies Ltd (Stage: CORRELATION_AND_SCORING)
        acme_name = "Acme Technologies Ltd"
        existing_acme = db.query(Case).filter(Case.subject_name == acme_name).first()
        if not existing_acme:
            c1 = Case(
                case_ref=_generate_case_ref(db),
                client_name="Global Investment Banking Corp",
                client_kyc_verified=True,
                msa_signed=True,
                purpose=PurposeEnum.corporate_due_diligence.value,
                subject_type=SubjectType.company.value,
                subject_name=acme_name,
                subject_identifier="L72200MH2010PLC123456",
                subject_city="Mumbai",
                subject_address="Express Towers, Nariman Point, Mumbai 400021",
                stage=CaseStage.CORRELATION_AND_SCORING.value,
                intake_approved=True,
                consent_verified=False,
                dossier_version=1,
                is_recalled=False,
                operator_id=op_user.id,
                reviewer_id=rev_user.id,
                created_by=op_user.id,
            )
            db.add(c1)
            db.flush()

            # Record 1: RDAP
            rdap_src = charter_map["DOMAIN_RDAP"]
            r1_run = SourceRun(
                case_id=c1.id,
                source_id=rdap_src.id,
                operator_id=op_user.id,
                query_input="acmetech.demo",
                status=SourceRunStatus.FOUND.value,
            )
            db.add(r1_run)
            db.flush()
            r1_content = json.dumps({
                "objectClassName": "domain",
                "handle": "DOM-ACME-DEMO-001",
                "ldhName": "acmetech.demo",
                "status": ["active", "clientTransferProhibited"],
                "entities": [{"roles": ["registrant"], "name": "Acme Technologies Ltd"}],
            }, indent=2)
            r1_hash = hashlib.sha256(r1_content.encode("utf-8")).hexdigest().lower()
            rec1 = Record(
                case_id=c1.id,
                source_run_id=r1_run.id,
                source_id=rdap_src.id,
                title="Domain RDAP: acmetech.demo",
                source_url="https://rdap.org/domain/acmetech.demo",
                raw_content=r1_content,
                content_type="application/json",
                snapshot_hash=r1_hash,
                extractor_version="m2-v1.0",
                triage_status=TriageStatus.ACCEPTED.value,
                triaged_by_id=op_user.id,
            )
            db.add(rec1)

            # Record 2: MCA
            mca_src = charter_map["MCA_MANUAL"]
            r2_run = SourceRun(
                case_id=c1.id,
                source_id=mca_src.id,
                operator_id=op_user.id,
                query_input="L72200MH2010PLC123456",
                status=SourceRunStatus.FOUND.value,
            )
            db.add(r2_run)
            db.flush()
            r2_content = (
                "Ministry of Corporate Affairs - Master Data\n"
                "CIN: L72200MH2010PLC123456\n"
                "Company Name: Acme Technologies Ltd\n"
                "Date of Incorporation: 15/04/2010\n"
                "Registered Address: Express Towers, Nariman Point, Mumbai 400021\n"
                "Status: Active\n"
            )
            r2_hash = hashlib.sha256(r2_content.encode("utf-8")).hexdigest().lower()
            rec2 = Record(
                case_id=c1.id,
                source_run_id=r2_run.id,
                source_id=mca_src.id,
                title="MCA21 Corporate Master Data Filing",
                source_url="https://www.mca.gov.in/filing/L72200MH2010PLC123456",
                raw_content=r2_content,
                content_type="text/plain",
                snapshot_hash=r2_hash,
                extractor_version="m2-v1.0",
                triage_status=TriageStatus.ACCEPTED.value,
                triaged_by_id=op_user.id,
            )
            db.add(rec2)

            # Record 3: eCourts Commercial Suit
            ecourts_src = charter_map["ECOURTS_MANUAL"]
            r3_run = SourceRun(
                case_id=c1.id,
                source_id=ecourts_src.id,
                operator_id=op_user.id,
                query_input="Acme Technologies Ltd",
                status=SourceRunStatus.FOUND.value,
            )
            db.add(r3_run)
            db.flush()
            r3_content = (
                "High Court of Bombay - Commercial Division\n"
                "Commercial Suit No. 1042/2022\n"
                "Plaintiff: Apex Infrastructure Logistics Ltd vs Defendant: Acme Technologies Ltd\n"
                "Subject Matter: Commercial breach of service level contract\n"
                "Status: Pending evidentiary hearings\n"
            )
            r3_hash = hashlib.sha256(r3_content.encode("utf-8")).hexdigest().lower()
            rec3 = Record(
                case_id=c1.id,
                source_run_id=r3_run.id,
                source_id=ecourts_src.id,
                title="Bombay High Court Commercial Suit 1042/2022",
                source_url="https://bombayhighcourt.nic.in/cases/1042_2022",
                raw_content=r3_content,
                content_type="text/plain",
                snapshot_hash=r3_hash,
                extractor_version="m2-v1.0",
                triage_status=TriageStatus.ACCEPTED.value,
                triaged_by_id=op_user.id,
            )
            db.add(rec3)
            db.flush()

            # Claims for Acme Technologies
            cl1 = Claim(
                case_id=c1.id,
                created_by_id=op_user.id,
                primary_record_id=rec2.id,
                extraction_method=ExtractionMethod.MANUAL.value,
                subject_entity=acme_name,
                predicate="INCORPORATED_CIN",
                object_value="L72200MH2010PLC123456",
                verbatim_quote="CIN: L72200MH2010PLC123456",
                source_reliability="A",
                identity_confidence=1,
                match_tier=MatchTier.TIER_1.value,
                matched_attributes_json=json.dumps(["CIN_EXACT"]),
                scoring_rationale="Exact CIN match on MCA21 official registry.",
                snapshot_hash=hashlib.sha256(f"{c1.id}:INCORPORATED_CIN:L72200MH2010PLC123456".encode()).hexdigest(),
                review_status=ReviewStatus.PENDING_REVIEW.value,
                is_adverse=False,
            )
            cl2 = Claim(
                case_id=c1.id,
                created_by_id=op_user.id,
                primary_record_id=rec2.id,
                extraction_method=ExtractionMethod.MANUAL.value,
                subject_entity=acme_name,
                predicate="REGISTERED_ADDRESS",
                object_value="Express Towers, Nariman Point, Mumbai 400021",
                verbatim_quote="Registered Address: Express Towers, Nariman Point, Mumbai 400021",
                source_reliability="A",
                identity_confidence=1,
                match_tier=MatchTier.TIER_1.value,
                matched_attributes_json=json.dumps(["CIN_EXACT", "ADDRESS_MATCH"]),
                scoring_rationale="Official registered corporate address from MCA21.",
                snapshot_hash=hashlib.sha256(f"{c1.id}:REGISTERED_ADDRESS:Express Towers".encode()).hexdigest(),
                review_status=ReviewStatus.PENDING_REVIEW.value,
                is_adverse=False,
            )
            cl3 = Claim(
                case_id=c1.id,
                created_by_id=op_user.id,
                primary_record_id=rec3.id,
                extraction_method=ExtractionMethod.MANUAL.value,
                subject_entity=acme_name,
                predicate="COMMERCIAL_LITIGATION",
                object_value="High Court of Bombay Commercial Suit No. 1042/2022 for breach of contract",
                verbatim_quote="Commercial Suit No. 1042/2022",
                source_reliability="A",
                identity_confidence=1,
                match_tier=MatchTier.TIER_1.value,
                matched_attributes_json=json.dumps(["NAME_EXACT"]),
                scoring_rationale="High Court official case record referencing named defendant.",
                snapshot_hash=hashlib.sha256(f"{c1.id}:COMMERCIAL_LITIGATION:1042_2022".encode()).hexdigest(),
                review_status=ReviewStatus.PENDING_REVIEW.value,
                is_adverse=True,
                adverse_category=AdverseCategory.LITIGATION_ACCUSED.value,
                finding_group_key="fg_acme_litigation",
            )
            db.add_all([cl1, cl2, cl3])
            log_action(
                db,
                action="case_created",
                user_id=op_user.id,
                case_id=c1.id,
                from_stage=CaseStage.INTAKE_DRAFT.value,
                to_stage=CaseStage.CORRELATION_AND_SCORING.value,
                allowed=True,
                detail={"demo_seeded": True, "subject": acme_name},
            )
            typer.echo(f"✓ Seeded demo case: {c1.case_ref} ({acme_name}) -> CORRELATION_AND_SCORING")
        else:
            typer.echo(f"  Skip case (exists): {acme_name}")

        # ── 2. Demo Case 2: Bharat Heavy Infra Pvt Ltd (Stage: INDEPENDENT_REVIEW)
        bharat_name = "Bharat Heavy Infra Pvt Ltd"
        existing_bharat = db.query(Case).filter(Case.subject_name == bharat_name).first()
        if not existing_bharat:
            c2 = Case(
                case_ref=_generate_case_ref(db),
                client_name="Standard Chartered Capital",
                client_kyc_verified=True,
                msa_signed=True,
                purpose=PurposeEnum.vendor_verification.value,
                subject_type=SubjectType.company.value,
                subject_name=bharat_name,
                subject_identifier="U45200DL2015PTC288990",
                subject_city="New Delhi",
                subject_address="Barakhamba Road, Connaught Place, New Delhi 110001",
                stage=CaseStage.INDEPENDENT_REVIEW.value,
                intake_approved=True,
                consent_verified=False,
                dossier_version=1,
                is_recalled=False,
                operator_id=op_user.id,
                reviewer_id=rev_user.id,
                created_by=op_user.id,
            )
            db.add(c2)
            db.flush()

            # Record 1: MCA Filing with default
            mca_src = charter_map["MCA_MANUAL"]
            r_b1_run = SourceRun(
                case_id=c2.id,
                source_id=mca_src.id,
                operator_id=op_user.id,
                query_input="U45200DL2015PTC288990",
                status=SourceRunStatus.FOUND.value,
            )
            db.add(r_b1_run)
            db.flush()
            r_b1_content = (
                "Ministry of Corporate Affairs - Master Data Filing\n"
                "CIN: U45200DL2015PTC288990\n"
                "Company: Bharat Heavy Infra Pvt Ltd\n"
                "Notices: Notice issued under Section 137 for delayed filing of financial statements (FY 2023-24)\n"
                "Status: Under Enquiry\n"
            )
            r_b1_hash = hashlib.sha256(r_b1_content.encode("utf-8")).hexdigest().lower()
            rec_b1 = Record(
                case_id=c2.id,
                source_run_id=r_b1_run.id,
                source_id=mca_src.id,
                title="MCA21 Statutory Filing Enquiry Notice",
                source_url="https://www.mca.gov.in/filing/U45200DL2015PTC288990",
                raw_content=r_b1_content,
                content_type="text/plain",
                snapshot_hash=r_b1_hash,
                extractor_version="m2-v1.0",
                triage_status=TriageStatus.ACCEPTED.value,
                triaged_by_id=op_user.id,
            )
            db.add(rec_b1)

            # Record 2: News Media Record
            news_src = charter_map["NEWS_MANUAL"]
            r_b2_run = SourceRun(
                case_id=c2.id,
                source_id=news_src.id,
                operator_id=op_user.id,
                query_input="Bharat Heavy Infra Pvt Ltd",
                status=SourceRunStatus.FOUND.value,
            )
            db.add(r_b2_run)
            db.flush()
            r_b2_content = (
                "Financial Express Report (14/08/2025)\n"
                "Subcontractors Stage Protest Over Delayed EPC Payments in Delhi NCR.\n"
                "Subcontractor union issues demand letter to Bharat Heavy Infra citing overdue invoices totaling Rs 4.2 Cr.\n"
            )
            r_b2_hash = hashlib.sha256(r_b2_content.encode("utf-8")).hexdigest().lower()
            rec_b2 = Record(
                case_id=c2.id,
                source_run_id=r_b2_run.id,
                source_id=news_src.id,
                title="Financial Express EPC Subcontractor Dispute Report",
                source_url="https://financialexpress.com/industry/bharat-heavy-infra-dispute",
                raw_content=r_b2_content,
                content_type="text/plain",
                snapshot_hash=r_b2_hash,
                extractor_version="m2-v1.0",
                triage_status=TriageStatus.ACCEPTED.value,
                triaged_by_id=op_user.id,
            )
            db.add(rec_b2)
            db.flush()

            # Claims for Bharat Heavy Infra
            cl_b1 = Claim(
                case_id=c2.id,
                created_by_id=op_user.id,
                primary_record_id=rec_b1.id,
                extraction_method=ExtractionMethod.MANUAL.value,
                subject_entity=bharat_name,
                predicate="INCORPORATED_CIN",
                object_value="U45200DL2015PTC288990",
                verbatim_quote="CIN: U45200DL2015PTC288990",
                source_reliability="A",
                identity_confidence=1,
                match_tier=MatchTier.TIER_1.value,
                matched_attributes_json=json.dumps(["CIN_EXACT"]),
                scoring_rationale="Official MCA21 master data filing CIN match.",
                snapshot_hash=hashlib.sha256(f"{c2.id}:INCORPORATED_CIN:U45200DL2015PTC288990".encode()).hexdigest(),
                review_status=ReviewStatus.PENDING_REVIEW.value,
                is_adverse=False,
            )
            cl_b2 = Claim(
                case_id=c2.id,
                created_by_id=op_user.id,
                primary_record_id=rec_b1.id,
                extraction_method=ExtractionMethod.MANUAL.value,
                subject_entity=bharat_name,
                predicate="STATUTORY_DEFAULT",
                object_value="Notice issued under Section 137 for delayed filing of financial statements",
                verbatim_quote="Notice issued under Section 137 for delayed filing of financial statements",
                source_reliability="A",
                identity_confidence=1,
                match_tier=MatchTier.TIER_1.value,
                matched_attributes_json=json.dumps(["CIN_EXACT"]),
                scoring_rationale="Government MCA statutory notice directly linked via corporate CIN.",
                snapshot_hash=hashlib.sha256(f"{c2.id}:STATUTORY_DEFAULT:S137".encode()).hexdigest(),
                review_status=ReviewStatus.PENDING_REVIEW.value,
                is_adverse=True,
                adverse_category="DEFAULT",
                finding_group_key="fg_tax_default",
            )
            cl_b3 = Claim(
                case_id=c2.id,
                created_by_id=op_user.id,
                primary_record_id=rec_b2.id,
                extraction_method=ExtractionMethod.MANUAL.value,
                subject_entity=bharat_name,
                predicate="SUBCONTRACTOR_DISPUTE",
                object_value="Subcontractor union issues demand letter citing overdue invoices of Rs 4.2 Cr",
                verbatim_quote="overdue invoices totaling Rs 4.2 Cr",
                source_reliability="C",
                identity_confidence=2,
                match_tier=MatchTier.TIER_2.value,
                matched_attributes_json=json.dumps(["NAME_EXACT", "CITY_MATCH"]),
                scoring_rationale="News report corroborated with corporate name and city of operation.",
                snapshot_hash=hashlib.sha256(f"{c2.id}:SUBCONTRACTOR_DISPUTE:overdue".encode()).hexdigest(),
                review_status=ReviewStatus.PENDING_REVIEW.value,
                is_adverse=True,
                adverse_category=AdverseCategory.LITIGATION_ACCUSED.value,
                finding_group_key="fg_supplier_dispute",
            )
            db.add_all([cl_b1, cl_b2, cl_b3])
            log_action(
                db,
                action="case_created",
                user_id=op_user.id,
                case_id=c2.id,
                from_stage=CaseStage.INTAKE_DRAFT.value,
                to_stage=CaseStage.INDEPENDENT_REVIEW.value,
                allowed=True,
                detail={"demo_seeded": True, "subject": bharat_name},
            )
            typer.echo(f"✓ Seeded demo case: {c2.case_ref} ({bharat_name}) -> INDEPENDENT_REVIEW")
        else:
            typer.echo(f"  Skip case (exists): {bharat_name}")

        # ── 3. Demo Case 3: CRICE Technologies Private Limited (Stage: RELEASE_GATE)
        crice_name = "CRICE Technologies Private Limited"
        existing_crice = db.query(Case).filter(Case.subject_name == crice_name).first()
        if not existing_crice:
            c3 = Case(
                case_ref=_generate_case_ref(db),
                client_name="Internal Compliance Audit",
                client_kyc_verified=True,
                msa_signed=True,
                purpose=PurposeEnum.vendor_verification.value,
                subject_type=SubjectType.company.value,
                subject_name=crice_name,
                subject_identifier="U72900KA2024PTC987654",
                subject_city="Bengaluru",
                subject_address="Koramangala 4th Block, Bengaluru 560034",
                stage=CaseStage.RELEASE_GATE.value,
                intake_approved=True,
                consent_verified=False,
                dossier_version=1,
                is_recalled=False,
                operator_id=op_user.id,
                reviewer_id=rev_user.id,
                created_by=op_user.id,
            )
            db.add(c3)
            db.flush()

            # Record 1: MCA
            mca_src = charter_map["MCA_MANUAL"]
            r_c1_run = SourceRun(
                case_id=c3.id,
                source_id=mca_src.id,
                operator_id=op_user.id,
                query_input="U72900KA2024PTC987654",
                status=SourceRunStatus.FOUND.value,
            )
            db.add(r_c1_run)
            db.flush()
            r_c1_content = (
                "MCA21 Statutory Master Data Record\n"
                "CIN: U72900KA2024PTC987654\n"
                "Company: CRICE Technologies Private Limited\n"
                "Incorporated: 02/01/2024\n"
                "Registered Office: Koramangala 4th Block, Bengaluru 560034\n"
                "Status: Active / Compliant\n"
            )
            r_c1_hash = hashlib.sha256(r_c1_content.encode("utf-8")).hexdigest().lower()
            rec_c1 = Record(
                case_id=c3.id,
                source_run_id=r_c1_run.id,
                source_id=mca_src.id,
                title="MCA21 Corporate Master Data Filing",
                source_url="https://www.mca.gov.in/filing/U72900KA2024PTC987654",
                raw_content=r_c1_content,
                content_type="text/plain",
                snapshot_hash=r_c1_hash,
                extractor_version="m2-v1.0",
                triage_status=TriageStatus.ACCEPTED.value,
                triaged_by_id=op_user.id,
            )
            db.add(rec_c1)

            # Record 2: GST
            gst_src = charter_map["GST_MANUAL"]
            r_c2_run = SourceRun(
                case_id=c3.id,
                source_id=gst_src.id,
                operator_id=op_user.id,
                query_input="29ABCDE1234F1Z5",
                status=SourceRunStatus.FOUND.value,
            )
            db.add(r_c2_run)
            db.flush()
            r_c2_content = (
                "Goods and Services Tax Network (GSTN) Portal\n"
                "GSTIN: 29ABCDE1234F1Z5\n"
                "Legal Name: CRICE Technologies Private Limited\n"
                "State: Karnataka\n"
                "Status: Active Regular Taxpayer\n"
            )
            r_c2_hash = hashlib.sha256(r_c2_content.encode("utf-8")).hexdigest().lower()
            rec_c2 = Record(
                case_id=c3.id,
                source_run_id=r_c2_run.id,
                source_id=gst_src.id,
                title="GSTN Taxpayer Verification Portal Record",
                source_url="https://services.gst.gov.in/services/searchtp",
                raw_content=r_c2_content,
                content_type="text/plain",
                snapshot_hash=r_c2_hash,
                extractor_version="m2-v1.0",
                triage_status=TriageStatus.ACCEPTED.value,
                triaged_by_id=op_user.id,
            )
            db.add(rec_c2)
            db.flush()

            # Claims for CRICE Technologies (Reviewed and Approved)
            now_utc = datetime.datetime.now(timezone.utc)
            cl_c1 = Claim(
                case_id=c3.id,
                created_by_id=op_user.id,
                primary_record_id=rec_c1.id,
                extraction_method=ExtractionMethod.MANUAL.value,
                subject_entity=crice_name,
                predicate="INCORPORATED_CIN",
                object_value="U72900KA2024PTC987654",
                verbatim_quote="CIN: U72900KA2024PTC987654",
                source_reliability="A",
                identity_confidence=1,
                match_tier=MatchTier.TIER_1.value,
                matched_attributes_json=json.dumps(["CIN_EXACT"]),
                scoring_rationale="Verified against MCA21 master data.",
                snapshot_hash=hashlib.sha256(f"{c3.id}:INCORPORATED_CIN:U72900KA2024PTC987654".encode()).hexdigest(),
                review_status=ReviewStatus.APPROVED.value,
                reviewed_by_id=rev_user.id,
                reviewed_at=now_utc,
                review_note="Verified against MCA master data registry.",
                is_adverse=False,
            )
            cl_c2 = Claim(
                case_id=c3.id,
                created_by_id=op_user.id,
                primary_record_id=rec_c2.id,
                extraction_method=ExtractionMethod.MANUAL.value,
                subject_entity=crice_name,
                predicate="GSTIN_ACTIVE",
                object_value="Active GSTIN 29ABCDE1234F1Z5 in Karnataka",
                verbatim_quote="GSTIN: 29ABCDE1234F1Z5",
                source_reliability="A",
                identity_confidence=1,
                match_tier=MatchTier.TIER_1.value,
                matched_attributes_json=json.dumps(["CIN_EXACT"]),
                scoring_rationale="Verified on GSTN portal as active regular taxpayer.",
                snapshot_hash=hashlib.sha256(f"{c3.id}:GSTIN_ACTIVE:29ABCDE1234F1Z5".encode()).hexdigest(),
                review_status=ReviewStatus.APPROVED.value,
                reviewed_by_id=rev_user.id,
                reviewed_at=now_utc,
                review_note="GST compliance certificate verified.",
                is_adverse=False,
            )
            db.add_all([cl_c1, cl_c2])
            db.flush()

            # Compile Dossier v1.0 for CRICE Technologies
            dossier = compile_dossier(db, c3, op_user)
            log_action(
                db,
                action="case_created",
                user_id=op_user.id,
                case_id=c3.id,
                from_stage=CaseStage.INTAKE_DRAFT.value,
                to_stage=CaseStage.RELEASE_GATE.value,
                allowed=True,
                detail={"demo_seeded": True, "subject": crice_name, "dossier_id": dossier.id},
            )
            typer.echo(f"✓ Seeded demo case: {c3.case_ref} ({crice_name}) -> RELEASE_GATE (Dossier v1.0 compiled)")
        else:
            typer.echo(f"  Skip case (exists): {crice_name}")

        db.commit()
        typer.echo(f"\nAll demo accounts use password: {password!r}")
    finally:
        db.close()


if __name__ == "__main__":
    app_cli()
