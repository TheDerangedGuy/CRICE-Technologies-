"""initial – create users, sessions, totp_used, cases, audit_log tables.

Revision ID: 0001
Revises:
Create Date: 2026-10-06

Notes:
 - Uses timezone-aware TIMESTAMP WITH TIME ZONE on Postgres; DATETIME on SQLite.
 - Postgres trigger blocks UPDATE/DELETE on audit_log at the DB level.
 - Enum values stored as VARCHAR with CHECK constraints.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Detect dialect for conditional DDL
def _is_postgres():
    bind = op.get_bind()
    return bind.dialect.name == "postgresql"


def upgrade() -> None:
    # ── users ────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=False),
        sa.Column("password_hash", sa.String(length=200), nullable=False),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.Column("totp_secret_enc", sa.Text(), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("failed_logins", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "role IN ('operator','reviewer','compliance_admin')",
            name="ck_users_role",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # ── sessions ─────────────────────────────────────────────────────────────
    op.create_table(
        "sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("session_id", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("mfa_verified", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("csrf_token", sa.String(length=64), nullable=False),
        sa.Column("last_active_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default="false"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sessions_session_id", "sessions", ["session_id"], unique=True)

    # ── totp_used ─────────────────────────────────────────────────────────────
    op.create_table(
        "totp_used",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("code", sa.String(length=6), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "code", name="uq_totp_used_user_code"),
    )

    # ── cases ─────────────────────────────────────────────────────────────────
    op.create_table(
        "cases",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("case_ref", sa.String(length=20), nullable=False),
        sa.Column("client_name", sa.String(length=200), nullable=False),
        sa.Column("purpose", sa.String(length=50), nullable=False),
        sa.Column("subject_type", sa.String(length=20), nullable=False),
        sa.Column("subject_name", sa.String(length=200), nullable=False),
        sa.Column("subject_identifier", sa.String(length=50), nullable=True),
        sa.Column("stage", sa.String(length=20), nullable=False),
        sa.Column("intake_approved", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("operator_id", sa.Integer(), nullable=False),
        sa.Column("reviewer_id", sa.Integer(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "subject_type IN ('company','person')",
            name="ck_cases_subject_type",
        ),
        sa.CheckConstraint(
            "stage IN ('INTAKE','COLLECT','PRE_AI_REVIEW','AI_PROCESSING',"
            "'POST_AI_REVIEW','BUILD','RELEASE','CLOSED')",
            name="ck_cases_stage",
        ),
        sa.ForeignKeyConstraint(["operator_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["reviewer_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cases_case_ref", "cases", ["case_ref"], unique=True)

    # ── audit_log ─────────────────────────────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("case_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    # ── Postgres-only: trigger blocking UPDATE/DELETE on audit_log ─────────────
    if _is_postgres():
        op.execute("""
            CREATE OR REPLACE FUNCTION audit_log_immutable()
            RETURNS TRIGGER AS $$
            BEGIN
                RAISE EXCEPTION 'audit_log is append-only: UPDATE and DELETE are forbidden';
            END;
            $$ LANGUAGE plpgsql;
        """)
        op.execute("""
            CREATE TRIGGER trg_audit_log_immutable
            BEFORE UPDATE OR DELETE ON audit_log
            FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
        """)


def downgrade() -> None:
    if _is_postgres():
        op.execute("DROP TRIGGER IF EXISTS trg_audit_log_immutable ON audit_log")
        op.execute("DROP FUNCTION IF EXISTS audit_log_immutable()")

    op.drop_table("audit_log")
    op.drop_index("ix_cases_case_ref", table_name="cases")
    op.drop_table("cases")
    op.drop_table("totp_used")
    op.drop_index("ix_sessions_session_id", table_name="sessions")
    op.drop_table("sessions")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
