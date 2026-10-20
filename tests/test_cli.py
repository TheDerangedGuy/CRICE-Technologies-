"""
tests/test_cli.py – Test CLI commands (create-admin and seed-demo).
"""
import pytest
from typer.testing import CliRunner
from app.cli import app_cli
from app.models import User, Case, UserRole, CaseStage

runner = CliRunner()


def test_cli_create_admin_success(db):
    """create-admin creates a new compliance_admin."""
    result = runner.invoke(
        app_cli,
        ["create-admin"],
        input="cli_admin@crice.test\nCLI Admin\nPassword123!Long\nPassword123!Long\n",
    )
    assert result.exit_code == 0
    assert "compliance_admin created" in result.stdout

    user = db.query(User).filter(User.email == "cli_admin@crice.test").first()
    assert user is not None
    assert user.role == UserRole.compliance_admin.value
    assert user.full_name == "CLI Admin"


def test_cli_create_admin_short_password(db):
    """create-admin rejects short passwords (< 12 characters)."""
    result = runner.invoke(
        app_cli,
        ["create-admin"],
        input="short_admin@crice.test\nShort Admin\nshort\nshort\n",
    )
    assert result.exit_code != 0
    assert "at least 12 characters" in result.output


def test_cli_seed_demo_idempotent(db):
    """seed-demo creates demo accounts and 2 demo cases without error, and is idempotent."""
    # First run
    result1 = runner.invoke(app_cli, ["seed-demo"])
    assert result1.exit_code == 0
    assert "Created operator" in result1.stdout or "operator@crice.demo" in result1.stdout
    assert "Seeded demo case" in result1.stdout

    # Verify users exist
    op = db.query(User).filter(User.email == "operator@crice.demo").first()
    rev = db.query(User).filter(User.email == "reviewer@crice.demo").first()
    adm = db.query(User).filter(User.email == "admin@crice.demo").first()
    assert op is not None
    assert rev is not None
    assert adm is not None

    # Verify cases exist across pipeline stages
    cases = db.query(Case).all()
    assert len(cases) >= 3
    stages = {c.stage for c in cases}
    assert CaseStage.CORRELATION_AND_SCORING.value in stages
    assert CaseStage.INDEPENDENT_REVIEW.value in stages
    assert CaseStage.RELEASE_GATE.value in stages

    for c in cases:
        assert c.client_kyc_verified is True
        assert c.msa_signed is True
        assert c.operator_id != c.reviewer_id
        assert c.operator_id == op.id
        assert c.reviewer_id == rev.id

    # Second run (idempotency check)
    result2 = runner.invoke(app_cli, ["seed-demo"])
    assert result2.exit_code == 0
    assert "Skip user (exists)" in result2.stdout
    assert "Skip case (exists)" in result2.stdout
