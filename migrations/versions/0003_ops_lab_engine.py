"""0003_ops_lab_engine – create ai_runs, claims, dossiers tables and case disambiguation fields.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-20
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgres():
    bind = op.get_bind()
    return bind.dialect.name == "postgresql"


def upgrade() -> None:
    # ── 1. Add disambiguation & AI columns to cases ───────────────────────────
    op.add_column("cases", sa.Column("subject_din", sa.String(length=20), nullable=True))
    op.add_column("cases", sa.Column("subject_pan_or_gstin", sa.String(length=25), nullable=True))
    op.add_column("cases", sa.Column("subject_dob_or_year", sa.String(length=20), nullable=True))
    op.add_column("cases", sa.Column("subject_father_or_spouse", sa.String(length=120), nullable=True))
    op.add_column("cases", sa.Column("subject_address", sa.String(length=500), nullable=True))
    op.add_column("cases", sa.Column("subject_city", sa.String(length=100), nullable=True))
    op.add_column(
        "cases",
        sa.Column(
            "ai_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true" if _is_postgres() else "1"),
        ),
    )
    op.add_column(
        "cases",
        sa.Column(
            "zero_findings_attested",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false" if _is_postgres() else "0"),
        ),
    )

    # ── 2. Create ai_runs table ───────────────────────────────────────────────
    op.create_table(
        "ai_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("operator_id", sa.Integer(), nullable=False),
        sa.Column("model_name", sa.String(length=80), nullable=False),
        sa.Column("prompt_version", sa.String(length=40), nullable=False, server_default="m4-v1.0"),
        sa.Column("input_record_ids_json", sa.Text(), nullable=False),
        sa.Column("raw_prompt", sa.Text(), nullable=False),
        sa.Column("raw_output", sa.Text(), nullable=False),
        sa.Column("claims_extracted_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claims_rejected_citation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('SUCCEEDED', 'FAILED', 'BYPASSED')",
            name="ck_ai_runs_status",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["operator_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ai_runs_case_id", "ai_runs", ["case_id"], unique=False)

    # ── 3. Create claims table ────────────────────────────────────────────────
    op.create_table(
        "claims",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("ai_run_id", sa.Integer(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=False),
        sa.Column("extraction_method", sa.String(length=20), nullable=False, server_default="AI_EXTRACTED"),
        sa.Column("subject_entity", sa.String(length=255), nullable=False),
        sa.Column("predicate", sa.String(length=120), nullable=False),
        sa.Column("object_value", sa.Text(), nullable=False),
        sa.Column("verbatim_quote", sa.Text(), nullable=True),
        sa.Column(
            "quote_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false" if _is_postgres() else "0"),
        ),
        sa.Column("primary_record_id", sa.Integer(), nullable=False),
        sa.Column("supporting_record_ids_json", sa.Text(), nullable=False, server_default="'[]'"),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("extractor_version", sa.String(length=30), nullable=False, server_default="m4-v1.0"),
        sa.Column("extracted_identifiers_json", sa.Text(), nullable=False, server_default="'{}'"),
        sa.Column("matched_attributes_json", sa.Text(), nullable=False, server_default="'[]'"),
        sa.Column("match_tier", sa.String(length=10), nullable=False, server_default="UNSCORED"),
        sa.Column("source_reliability", sa.String(length=1), nullable=False),
        sa.Column("reliability_downgrade_reason", sa.Text(), nullable=True),
        sa.Column("identity_confidence", sa.Integer(), nullable=False, server_default="6"),
        sa.Column("scoring_rationale", sa.Text(), nullable=True),
        sa.Column(
            "is_adverse",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false" if _is_postgres() else "0"),
        ),
        sa.Column("adverse_category", sa.String(length=50), nullable=True),
        sa.Column("finding_group_key", sa.String(length=64), nullable=True),
        sa.Column("origin_domain", sa.String(length=120), nullable=True),
        sa.Column("review_status", sa.String(length=20), nullable=False, server_default="PENDING_REVIEW"),
        sa.Column("reviewed_by_id", sa.Integer(), nullable=True),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dossier_section", sa.String(length=35), nullable=False, server_default="EXCLUDED"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "extraction_method IN ('AI_EXTRACTED', 'MANUAL')",
            name="ck_claims_extraction_method",
        ),
        sa.CheckConstraint(
            "match_tier IN ('TIER_1', 'TIER_2', 'TIER_3', 'UNSCORED')",
            name="ck_claims_match_tier",
        ),
        sa.CheckConstraint(
            "source_reliability IN ('A', 'B', 'C', 'D', 'E', 'F')",
            name="ck_claims_source_reliability",
        ),
        sa.CheckConstraint(
            "identity_confidence BETWEEN 1 AND 6",
            name="ck_claims_identity_confidence",
        ),
        sa.CheckConstraint(
            "adverse_category IS NULL OR adverse_category IN ('FRAUD', 'CONVICTION', 'DEFAULT', 'SANCTIONS', 'LITIGATION_ACCUSED', 'REGULATORY_PENALTY')",
            name="ck_claims_adverse_category",
        ),
        sa.CheckConstraint(
            "review_status IN ('PENDING_REVIEW', 'APPROVED', 'REJECTED')",
            name="ck_claims_review_status",
        ),
        sa.CheckConstraint(
            "dossier_section IN ('CONFIRMED_FINDING', 'UNRESOLVED_POSSIBLE_MATCH', 'EXCLUDED')",
            name="ck_claims_dossier_section",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["ai_run_id"], ["ai_runs.id"]),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["primary_record_id"], ["records.id"]),
        sa.ForeignKeyConstraint(["reviewed_by_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_claims_case_id", "claims", ["case_id"], unique=False)

    # ── 4. Create dossiers table ──────────────────────────────────────────────
    op.create_table(
        "dossiers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("compiled_by_id", sa.Integer(), nullable=False),
        sa.Column("html_content", sa.Text(), nullable=False),
        sa.Column("pdf_bytes_b64", sa.Text(), nullable=True),
        sa.Column("dossier_hash", sa.String(length=64), nullable=False),
        sa.Column("coverage_manifest_json", sa.Text(), nullable=False),
        sa.Column("confirmed_findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("unresolved_matches_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("delivery_token", sa.String(length=64), nullable=True),
        sa.Column("delivery_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_revoked",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false" if _is_postgres() else "0"),
        ),
        sa.Column("released_by_id", sa.Integer(), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["compiled_by_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["released_by_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dossiers_case_id", "dossiers", ["case_id"], unique=False)
    op.create_index("ix_dossiers_delivery_token", "dossiers", ["delivery_token"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_dossiers_delivery_token", table_name="dossiers")
    op.drop_index("ix_dossiers_case_id", table_name="dossiers")
    op.drop_table("dossiers")

    op.drop_index("ix_claims_case_id", table_name="claims")
    op.drop_table("claims")

    op.drop_index("ix_ai_runs_case_id", table_name="ai_runs")
    op.drop_table("ai_runs")

    op.drop_column("cases", "zero_findings_attested")
    op.drop_column("cases", "ai_enabled")
    op.drop_column("cases", "subject_city")
    op.drop_column("cases", "subject_address")
    op.drop_column("cases", "subject_father_or_spouse")
    op.drop_column("cases", "subject_dob_or_year")
    op.drop_column("cases", "subject_pan_or_gstin")
    op.drop_column("cases", "subject_din")
