"""
app/auth/roles.py – FastAPI dependencies for authentication and role enforcement.

get_current_user:     raises HTTP 401 if not fully authenticated (password + MFA).
require_role(*roles): wraps get_current_user and additionally checks role membership.

A 401 is caught by the exception handler in main.py and redirected to /login.
"""
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User, UserRole


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """
    Dependency: returns the authenticated User or raises HTTP 401.
    Requires that both password AND TOTP have been completed (session["mfa"] is True).
    """
    session = getattr(request.state, "session", None)
    if not session or not session.get("mfa"):
        raise HTTPException(status_code=401, detail="Authentication required")

    user: User | None = db.get(User, session["uid"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Authentication required")

    return user


def require_role(*roles: UserRole):
    """
    Dependency factory: ensures the current user has one of the given roles.
    Example:
        admin_only = require_role(UserRole.compliance_admin)
    """
    def _dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status_code=403, detail="You don't have permission to do that.")
        return user

    return _dep


# Pre-built dependency for compliance_admin-only routes.
require_compliance_admin = require_role(UserRole.compliance_admin)
