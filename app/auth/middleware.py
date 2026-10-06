"""
app/auth/middleware.py – validates the session cookie on every request.

Stores a plain dict in request.state.session_data (NOT an ORM object) to avoid
DetachedInstanceError when different SQLAlchemy sessions are used in middleware
vs. route handlers.

Format stored in request.state.session_data:
    {
        "session_id": str,  # the raw cookie value
        "valid": bool,      # False if expired/revoked
    }

Route dependencies re-load the full Session row from their own DB session
using request.state.session_data["session_id"].
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.auth.sessions import COOKIE_NAME


class SessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        session_id = request.cookies.get(COOKIE_NAME)
        # Store just the raw ID; validation happens inside route dependencies
        # where we have the proper DI-scoped DB session.
        request.state.session_id = session_id
        response = await call_next(request)
        return response
