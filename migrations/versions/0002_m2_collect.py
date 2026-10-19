"""m2_collect – create source_charter, source_runs, and records tables with evidence immutability.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-19

Notes:
 - Creates source_charter for governed intelligence sources.
 - Creates source_runs for tracking collection attempts (FOUND, NOT_FOUND, FAILED).
 - Creates records for raw evidence payloads with SHA-256 snapshot hashes and triage status.
 - Postgres trigger blocks DELETE on records and blocks UPDATE of evidence payload/hash/url/retrieved_at.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgres():
    bind = op.get_bind()
    return bind.dialect.name == "postgresql"


def upgrade() -> None:
    # ── source_charter ────────────────────────────────────────────────────────
    op.create_table(
        "source_charter",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=50), nullable=False),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("owner", sa.String(length=120), nullable=False),
        sa.Column("tier", sa.String(length=1), nullable=False),
        sa.Column("default_reliability", sa.String(length=1), nullable=False),
        sa.Column("collection_mode", sa.String(length=20), nullable=False),
        sa.Column("legal_basis", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("tier IN ('A','B','C')", name="ck_source_charter_tier"),
        sa.CheckConstraint(
            "default_reliability IN ('A','B','C','D','E','F')",
            name="ck_source_charter_reliability",
        ),
        sa.CheckConstraint(
            "collection_mode IN ('AUTOMATED','MANUAL_CAPTURE')",
            name="ck_source_charter_mode",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_source_charter_code", "source_charter", ["code"], unique=True)

    # ── source_runs ───────────────────────────────────────────────────────────
    op.create_table(
        "source_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("operator_id", sa.Integer(), nullable=False),
        sa.Column("query_input", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("error_detail", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('FOUND','NOT_FOUND','FAILED')",
            name="ck_source_runs_status",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["source_id"], ["source_charter.id"]),
        sa.ForeignKeyConstraint(["operator_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_source_runs_case_id", "source_runs", ["case_id"], unique=False)

    # ── records ───────────────────────────────────────────────────────────────
    op.create_table(
        "records",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.Integer(), nullable=False),
        sa.Column("source_run_id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("source_url", sa.String(length=500), nullable=False),
        sa.Column("raw_content", sa.Text(), nullable=False),
        sa.Column("content_type", sa.String(length=50), nullable=False, server_default="application/json"),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("extractor_version", sa.String(length=30), nullable=False, server_default="m2-v1.0"),
        sa.Column("retrieved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("triage_status", sa.String(length=20), nullable=False, server_default="PENDING_TRIAGE"),
        sa.Column("triage_note", sa.Text(), nullable=True),
        sa.Column("triaged_by_id", sa.Integer(), nullable=True),
        sa.Column("triaged_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "triage_status IN ('PENDING_TRIAGE','ACCEPTED','REJECTED')",
            name="ck_records_triage_status",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.ForeignKeyConstraint(["source_run_id"], ["source_runs.id"]),
        sa.ForeignKeyConstraint(["source_id"], ["source_charter.id"]),
        sa.ForeignKeyConstraint(["triaged_by_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_records_case_id", "records", ["case_id"], unique=False)

    # ── Postgres-only: trigger enforcing evidence immutability on records ─────
    if _is_postgres():
        op.execute("""
            CREATE OR REPLACE FUNCTION record_evidence_immutable()
            RETURNS TRIGGER AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'records are immutable: DELETE is forbidden';
                ELSIF TG_OP = 'UPDATE' THEN
                    IF OLD.raw_content != NEW.raw_content OR OLD.snapshot_hash != NEW.snapshot_hash OR OLD.source_url != NEW.source_url OR OLD.retrieved_at != NEW.retrieved_at THEN
                        RAISE EXCEPTION 'record evidence is immutable: payload and hash cannot be modified';
                    END IF;
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
        """)
        op.execute("""
            CREATE TRIGGER trg_records_immutable
            BEFORE UPDATE OR DELETE ON records
            FOR EACH ROW EXECUTE FUNCTION record_evidence_immutable();
        """)


def downgrade() -> None:
    if _is_postgres():
        op.execute("DROP TRIGGER IF EXISTS trg_records_immutable ON records")
        op.execute("DROP FUNCTION IF EXISTS record_evidence_immutable()")

    op.drop_index("ix_records_case_id", table_name="records")
    op.drop_table("records")
    op.drop_index("ix_source_runs_case_id", table_name="source_runs")
    op.drop_table("source_runs")
    op.drop_index("ix_source_charter_code", table_name="source_charter")
    op.drop_table("source_charter")
