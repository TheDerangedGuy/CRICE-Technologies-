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

import typer
import pyotp
from sqlalchemy.orm import sessionmaker

from app.db import Base, _get_engine
from app.models import (
    Case,
    CaseStage,
    PurposeEnum,
    Record,
    SourceCharter,
    SourceRun,
    SourceRunStatus,
    SubjectType,
    TriageStatus,
    User,
    UserRole,
)
from app.auth.password import hash_password, _MIN_LENGTH
from app.auth.totp_crypto import encrypt_totp_secret
from app.audit.writer import log_action
from app.collect.charter import seed_source_charter

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
        ..., prompt=True, hide_input=True, confirmation_prompt=True,
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

        # Seed 2 demo cases: listed company and CRICE entity
        demo_cases_spec = [
            {
                "subject_name": "Acme Technologies Ltd",
                "subject_identifier": "L72200MH2010PLC123456",
                "client_name": "Global Investment Banking Corp",
                "purpose": PurposeEnum.corporate_due_diligence.value,
                "subject_type": SubjectType.company.value,
                "sample_source": "DOMAIN_RDAP",
                "sample_query": "acmetech.demo",
                "sample_title": "Domain RDAP: acmetech.demo",
                "sample_url": "https://rdap.org/domain/acmetech.demo",
                "sample_content": json.dumps({
                    "objectClassName": "domain",
                    "handle": "DOM-ACME-DEMO-001",
                    "ldhName": "acmetech.demo",
                    "status": ["active", "clientTransferProhibited"],
                    "entities": [{"roles": ["registrant"], "name": "Acme Technologies Ltd Admin"}],
                }, indent=2, sort_keys=True),
            },
            {
                "subject_name": "CRICE Technologies Private Limited",
                "subject_identifier": "U72900KA2024PTC987654",
                "client_name": "Internal Compliance Audit",
                "purpose": PurposeEnum.vendor_verification.value,
                "subject_type": SubjectType.company.value,
                "sample_source": "MCA_MANUAL",
                "sample_query": "U72900KA2024PTC987654",
                "sample_title": "MCA21 Corporate Master Data Filing",
                "sample_url": "https://www.mca.gov.in/mcafoportal/companyLLPMasterData.do",
                "sample_content": "MCA21 Statutory Master Data Record\nCIN: U72900KA2024PTC987654\nCompany: CRICE Technologies Private Limited\nStatus: Active / Listed",
            },
        ]

        for spec in demo_cases_spec:
            existing_case = (
                db.query(Case)
                .filter(Case.subject_name == spec["subject_name"])
                .first()
            )
            if not existing_case:
                case = Case(
                    case_ref=_generate_case_ref(db),
                    client_name=spec["client_name"],
                    client_kyc_verified=True,
                    msa_signed=True,
                    purpose=spec["purpose"],
                    subject_type=spec["subject_type"],
                    subject_name=spec["subject_name"],
                    subject_identifier=spec["subject_identifier"],
                    stage=CaseStage.COLLECT.value,
                    intake_approved=True,
                    consent_verified=False,
                    dossier_version=1,
                    is_recalled=False,
                    operator_id=op_user.id,
                    reviewer_id=rev_user.id,
                    created_by=op_user.id,
                )
                db.add(case)
                db.flush()

                log_action(
                    db,
                    action="case_created",
                    user_id=op_user.id,
                    case_id=case.id,
                    from_stage=CaseStage.INTAKE_DRAFT.value,
                    to_stage=CaseStage.COLLECT.value,
                    allowed=True,
                    detail={"demo_seeded": True, "subject": spec["subject_name"]},
                )
                typer.echo(f"✓ Seeded demo case: {case.case_ref} ({spec['subject_name']})")

                # Seed sample completed source run and accepted evidence record
                src_charter = charter_map.get(spec["sample_source"])
                if src_charter:
                    run = SourceRun(
                        case_id=case.id,
                        source_id=src_charter.id,
                        operator_id=op_user.id,
                        query_input=spec["sample_query"],
                        status=SourceRunStatus.FOUND.value,
                    )
                    db.add(run)
                    db.flush()

                    content = spec["sample_content"]
                    h = hashlib.sha256(content.encode("utf-8")).hexdigest().lower()
                    rec = Record(
                        case_id=case.id,
                        source_run_id=run.id,
                        source_id=src_charter.id,
                        title=spec["sample_title"],
                        source_url=spec["sample_url"],
                        raw_content=content,
                        content_type="application/json" if spec["sample_source"] == "DOMAIN_RDAP" else "text/plain",
                        snapshot_hash=h,
                        extractor_version="m2-v1.0",
                        triage_status=TriageStatus.ACCEPTED.value,
                        triaged_by_id=op_user.id,
                    )
                    db.add(rec)
                    db.flush()
                    typer.echo(f"  ✓ Seeded evidence run: {spec['sample_source']} (SHA-256: {h[:12]}...)")
            else:
                typer.echo(f"  Skip case (exists): {spec['subject_name']}")

        db.commit()
        typer.echo(f"\nAll demo accounts use password: {password!r}")
    finally:
        db.close()


if __name__ == "__main__":
    app_cli()
