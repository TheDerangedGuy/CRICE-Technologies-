"""
app/cli.py – management CLI.

Commands:
  create-admin   Create the first compliance_admin user.
  seed-demo      Create demo operator / reviewer accounts for local development.

Usage (from repo root):
  python -m app.cli create-admin
  python -m app.cli seed-demo
"""
import secrets
import sys

import typer
import pyotp

# Set up minimal env before importing app modules
import os
os.environ.setdefault("DATABASE_URL", "")  # Will error loudly if not set

from app.db import Base, _get_engine
from app.models import User, UserRole
from app.auth.password import hash_password, _MIN_LENGTH
from app.auth.totp_crypto import encrypt_totp_secret
from sqlalchemy.orm import sessionmaker

app_cli = typer.Typer(name="crice", help="CRICE Lab management CLI")


def _get_db():
    from app.db import _get_engine
    factory = sessionmaker(bind=_get_engine())
    return factory()


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


@app_cli.command()
def seed_demo():
    """Create demo accounts for local development (idempotent)."""
    db = _get_db()
    password = "Demo1234!Demo"

    demos = [
        dict(email="operator@crice.demo", full_name="Demo Operator", role=UserRole.operator.value),
        dict(email="reviewer@crice.demo", full_name="Demo Reviewer", role=UserRole.reviewer.value),
        dict(email="admin@crice.demo", full_name="Demo Admin", role=UserRole.compliance_admin.value),
    ]
    for d in demos:
        if not db.query(User).filter(User.email == d["email"]).first():
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
        else:
            typer.echo(f"  Skip (exists): {d['email']}")

    db.commit()
    typer.echo(f"\nAll demo accounts use password: {password!r}")


if __name__ == "__main__":
    app_cli()
