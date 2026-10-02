"""
app/auth/sessions.py – signed, stateless session cookies via itsdangerous.

Session payload:
    {
        "uid":  <user_id: int>,
        "mfa":  <bool – True only after TOTP is verified>,
        "csrf": <random hex – used for CSRF token validation>
    }

The cookie is HttpOnly + SameSite=Lax; CSRF protection is done by
comparing the "csrf" field from the signed cookie with the hidden _csrf
form field on every non-GET request.
"""
import secrets
from typing import Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

import app.config as config


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(config.SECRET_KEY, salt="crice-session")


def create_session_token(user_id: int, mfa_ok: bool) -> str:
    """Create a signed session token; embeds a fresh CSRF nonce."""
    payload = {
        "uid": user_id,
        "mfa": mfa_ok,
        "csrf": secrets.token_hex(24),
    }
    return _serializer().dumps(payload)


def load_session_token(token: str) -> Optional[dict]:
    """
    Verify and decode a session token.
    Returns the payload dict, or None if the token is invalid / expired.
    """
    try:
        return _serializer().loads(token, max_age=config.SESSION_MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
