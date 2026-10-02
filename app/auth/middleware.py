"""
app/auth/middleware.py – extracts and validates the session cookie on every request.

Stores the decoded session payload in request.state.session.
If the cookie is missing or invalid, request.state.session is None.
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.auth.sessions import load_session_token


class SessionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        token = request.cookies.get("session")
        request.state.session = load_session_token(token) if token else None
        response = await call_next(request)
        return response
