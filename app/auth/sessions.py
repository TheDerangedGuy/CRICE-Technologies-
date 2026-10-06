"""
app/auth/sessions.py – server-side DB-backed sessions.

The cookie holds only an opaque random session_id (not a payload).
Session rows record:
  - user_id
  - mfa_verified flag
  - csrf_token (for CSRF protection)
  - last_active_at (idle timeout)
  - created_at (absolute timeout)
  - revoked flag (explicit logout / deactivation)

Timeouts:
  - Idle: SESSION_IDLE_SECONDS (default 8 h) – updated on every authenticated request
  - Absolute: SESSION_ABSOLUTE_SECONDS (default 24 h) – never extended

Revocation:
  - logout: sets revoked=True
  - user deactivation: query all non-revoked sessions for user and revoke them
"""
import secrets
import datetime
from typing import Optional

from sqlalchemy.orm import Session as DbSession

import app.config as config
from app.models import Session as SessionModel


_COOKIE_NAME = "sid"


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ── Create ───────────────────────────────────────────────────────────────────


def create_session(db: DbSession, user_id: int, mfa_verified: bool) -> tuple[str, str]:
    """
    Create a new session row.
    Returns (session_id, csrf_token) to embed in the cookie and form.
    """
    session_id = secrets.token_hex(32)
    csrf_token = secrets.token_hex(32)
    row = SessionModel(
        session_id=session_id,
        user_id=user_id,
        mfa_verified=mfa_verified,
        csrf_token=csrf_token,
        last_active_at=_now(),
        created_at=_now(),
        revoked=False,
    )
    db.add(row)
    db.commit()
    return session_id, csrf_token


# ── Load ─────────────────────────────────────────────────────────────────────


def load_session(db: DbSession, session_id: Optional[str]) -> Optional[SessionModel]:
    """
    Load and validate a session by its ID.
    Returns None if the session is missing, revoked, or expired.
    Does NOT touch last_active_at (caller updates it after auth check).
    """
    if not session_id:
        return None

    row: Optional[SessionModel] = (
        db.query(SessionModel)
        .filter(SessionModel.session_id == session_id)
        .first()
    )
    if row is None or row.revoked:
        return None

    now = _now()

    # Absolute timeout
    age = (now - _ensure_tz(row.created_at)).total_seconds()
    if age > config.SESSION_ABSOLUTE_SECONDS:
        _revoke_row(db, row)
        return None

    # Idle timeout
    idle = (now - _ensure_tz(row.last_active_at)).total_seconds()
    if idle > config.SESSION_IDLE_SECONDS:
        _revoke_row(db, row)
        return None

    return row


def touch_session(db: DbSession, row: SessionModel) -> None:
    """Update last_active_at to reset the idle timer."""
    row.last_active_at = _now()
    db.commit()


# ── Promote MFA ──────────────────────────────────────────────────────────────


def promote_to_mfa(db: DbSession, row: SessionModel) -> None:
    """Mark the session as MFA-verified (called after successful TOTP check)."""
    row.mfa_verified = True
    db.commit()


# ── Revocation ────────────────────────────────────────────────────────────────


def revoke_session(db: DbSession, row: SessionModel) -> None:
    """Revoke a single session (logout)."""
    _revoke_row(db, row)


def revoke_all_user_sessions(db: DbSession, user_id: int) -> None:
    """Revoke all active sessions for a user (deactivation / MFA reset)."""
    db.query(SessionModel).filter(
        SessionModel.user_id == user_id,
        SessionModel.revoked.is_(False),
    ).update({"revoked": True})
    db.commit()


# ── Cookie helpers ────────────────────────────────────────────────────────────


COOKIE_NAME = _COOKIE_NAME


def set_session_cookie(response, session_id: str) -> None:
    response.set_cookie(
        COOKIE_NAME,
        session_id,
        httponly=True,
        samesite="lax",
        secure=config.SECURE_COOKIES,
        max_age=config.SESSION_ABSOLUTE_SECONDS,
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(COOKIE_NAME)


# ── Internals ─────────────────────────────────────────────────────────────────


def _revoke_row(db: DbSession, row: SessionModel) -> None:
    row.revoked = True
    db.commit()


def _ensure_tz(dt: datetime.datetime) -> datetime.datetime:
    """Attach UTC tz if the datetime is naive (SQLite stores without tz)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt
