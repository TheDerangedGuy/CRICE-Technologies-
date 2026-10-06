"""
app/auth/roles.py – FastAPI dependencies for authentication and role enforcement.
"""
from typing import Optional

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.sessions import load_session, touch_session
from app.db import get_db
from app.models import Session as SessionModel, User, UserRole


def get_session_row(
    request: Request,
    db: Session = Depends(get_db),
) -> Optional[SessionModel]:
    """
    Dependency: load and validate the Session row for this request.
    Returns the row (possibly with mfa_verified=False) or None.
    Touches last_active_at when mfa_verified.
    """
    session_id: Optional[str] = getattr(request.state, "session_id", None)
    row = load_session(db, session_id)
    if row and row.mfa_verified:
        touch_session(db, row)
    return row


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    Dependency: returns the authenticated User or raises HTTP 401.
    Requires that the session exists, is not expired/revoked, and mfa_verified=True.
    """
    sess = get_session_row(request, db)
    if sess is None or not sess.mfa_verified:
        raise HTTPException(status_code=401, detail="Authentication required")

    user: Optional[User] = db.get(User, sess.user_id)
    if user is None or not user.is_active:
        if sess:
            from app.auth.sessions import revoke_session
            revoke_session(db, sess)
        raise HTTPException(status_code=401, detail="Authentication required")

    return user


def require_role(*roles: UserRole):
    """Dependency factory: ensures the current user has one of the given roles."""
    def _dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in [r.value for r in roles]:
            raise HTTPException(status_code=403, detail="You don't have permission to do that.")
        return user
    return _dep


require_compliance_admin = require_role(UserRole.compliance_admin)
