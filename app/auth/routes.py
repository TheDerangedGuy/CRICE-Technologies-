"""
app/auth/routes.py – login, MFA, and logout routes.

Flow:
  1. GET /login          → password form
  2. POST /login         → verify password → partial session (mfa=False) → redirect to /mfa or /mfa/setup
  3. GET /mfa            → TOTP entry form
  4. POST /mfa           → verify TOTP → full session (mfa=True) → redirect to /cases
  5. GET /mfa/setup      → show QR code + confirm first TOTP (only when mfa_enabled=False)
  6. POST /mfa/setup     → verify TOTP → set mfa_enabled=True → full session → redirect to /cases
  7. GET /logout         → clear cookie → redirect to /login

Lockout: 5 consecutive bad passwords → locked_until = now + 15 min.
CSRF: every state-changing POST checks the _csrf form field against
      the "csrf" value embedded in the signed session cookie.
"""
import base64
import datetime
import io
from typing import Optional, Union

import pyotp
import qrcode
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.orm import Session

import app.config as config
from app.audit.writer import log_action
from app.auth.password import verify_password
from app.auth.sessions import create_session_token
from app.db import get_db
from app.models import User
from app.templates_config import templates

router = APIRouter(tags=["auth"])

_LOCKOUT_ATTEMPTS = config.LOCKOUT_ATTEMPTS
_LOCKOUT_DURATION = datetime.timedelta(minutes=config.LOCKOUT_MINUTES)


# ── Internal helpers ──────────────────────────────────────────────────────────


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _session(request: Request) -> Optional[dict]:
    return getattr(request.state, "session", None)


def _render(
    request: Request,
    template: str,
    ctx: dict,
    status: int = 200,
) -> HTMLResponse:
    sess = _session(request)
    ctx.setdefault("request", request)
    ctx.setdefault("current_user", None)
    ctx.setdefault("csrf_token", sess.get("csrf", "") if sess else "")
    return templates.TemplateResponse(template, ctx, status_code=status)


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        "session",
        token,
        httponly=True,
        samesite="lax",
        secure=config.SECURE_COOKIES,
        max_age=config.SESSION_MAX_AGE,
    )


def _make_qr_b64(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def _csrf_ok(request: Request, submitted_token: str) -> bool:
    sess = _session(request)
    return bool(sess and submitted_token == sess.get("csrf"))


# ── GET /login ────────────────────────────────────────────────────────────────


@router.get("/login", response_model=None)
def login_get(request: Request) -> Response:
    sess = _session(request)
    if sess:
        if sess.get("mfa"):
            return RedirectResponse("/cases", status_code=302)
        return RedirectResponse("/mfa", status_code=302)
    return _render(request, "auth/login.html", {"error": None})


# ── POST /login ───────────────────────────────────────────────────────────────


@router.post("/login", response_model=None)
async def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> Response:
    ip = _ip(request)
    now = datetime.datetime.now(datetime.timezone.utc)

    user: Optional[User] = db.query(User).filter(
        User.email == email.strip().lower()
    ).first()

    def _bad_creds() -> Response:
        return _render(request, "auth/login.html", {"error": "Invalid email or password."}, 401)

    if not user or not user.is_active:
        return _bad_creds()

    # Lockout check
    if user.locked_until:
        lu = user.locked_until
        if lu.tzinfo is None:
            lu = lu.replace(tzinfo=datetime.timezone.utc)
        if lu > now:
            mins = int((lu - now).total_seconds() / 60) + 1
            return _render(
                request,
                "auth/login.html",
                {"error": f"Account locked. Try again in {mins} minute(s)."},
                401,
            )

    # Password check
    if not verify_password(user.password_hash, password):
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= _LOCKOUT_ATTEMPTS:
            user.locked_until = now + _LOCKOUT_DURATION
            db.flush()
            log_action(
                db,
                action="account_locked",
                user_id=user.id,
                detail={"reason": "Too many failed login attempts"},
                ip=ip,
            )
        db.commit()
        return _bad_creds()

    # Password OK – reset counters
    user.failed_logins = 0
    user.locked_until = None
    db.commit()

    # Issue partial session (mfa not yet complete)
    token = create_session_token(user.id, mfa_ok=False)
    dest = "/mfa" if user.mfa_enabled else "/mfa/setup"
    resp = RedirectResponse(dest, status_code=302)
    _set_session_cookie(resp, token)
    return resp


# ── GET /mfa ──────────────────────────────────────────────────────────────────


@router.get("/mfa", response_model=None)
def mfa_get(request: Request, db: Session = Depends(get_db)) -> Response:
    sess = _session(request)
    if not sess:
        return RedirectResponse("/login", status_code=302)
    if sess.get("mfa"):
        return RedirectResponse("/cases", status_code=302)
    user: Optional[User] = db.get(User, sess["uid"])
    if not user or not user.mfa_enabled:
        return RedirectResponse("/mfa/setup", status_code=302)
    return _render(request, "auth/mfa.html", {"error": None})


# ── POST /mfa ─────────────────────────────────────────────────────────────────


@router.post("/mfa", response_model=None)
async def mfa_post(
    request: Request,
    totp_code: str = Form(...),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
) -> Response:
    sess = _session(request)
    if not sess or sess.get("mfa"):
        return RedirectResponse("/login", status_code=302)

    if not _csrf_ok(request, csrf_token):
        return _render(request, "auth/mfa.html",
                       {"error": "Security check failed. Please try again."}, 403)

    user: Optional[User] = db.get(User, sess["uid"])
    if not user or not user.totp_secret:
        return RedirectResponse("/login", status_code=302)

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(totp_code.strip(), valid_window=1):
        return _render(request, "auth/mfa.html", {"error": "Invalid code. Please try again."}, 401)

    log_action(db, action="login", user_id=user.id, detail={"method": "totp"}, ip=_ip(request))
    db.commit()

    new_token = create_session_token(user.id, mfa_ok=True)
    resp = RedirectResponse("/cases", status_code=302)
    _set_session_cookie(resp, new_token)
    return resp


# ── GET /mfa/setup ────────────────────────────────────────────────────────────


@router.get("/mfa/setup", response_model=None)
def mfa_setup_get(request: Request, db: Session = Depends(get_db)) -> Response:
    sess = _session(request)
    if not sess:
        return RedirectResponse("/login", status_code=302)
    if sess.get("mfa"):
        return RedirectResponse("/cases", status_code=302)
    user: Optional[User] = db.get(User, sess["uid"])
    if not user:
        return RedirectResponse("/login", status_code=302)
    if user.mfa_enabled:
        return RedirectResponse("/mfa", status_code=302)

    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.commit()

    uri = pyotp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email, issuer_name="CRICE Lab"
    )
    return _render(request, "auth/mfa_setup.html",
                   {"totp_uri": uri, "qr_b64": _make_qr_b64(uri), "error": None})


# ── POST /mfa/setup ───────────────────────────────────────────────────────────


@router.post("/mfa/setup", response_model=None)
async def mfa_setup_post(
    request: Request,
    totp_code: str = Form(...),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
) -> Response:
    sess = _session(request)
    if not sess or sess.get("mfa"):
        return RedirectResponse("/login", status_code=302)

    if not _csrf_ok(request, csrf_token):
        return RedirectResponse("/mfa/setup", status_code=302)

    user: Optional[User] = db.get(User, sess["uid"])
    if not user or not user.totp_secret:
        return RedirectResponse("/login", status_code=302)

    totp = pyotp.TOTP(user.totp_secret)
    if not totp.verify(totp_code.strip(), valid_window=1):
        uri = totp.provisioning_uri(name=user.email, issuer_name="CRICE Lab")
        return _render(
            request,
            "auth/mfa_setup.html",
            {"totp_uri": uri, "qr_b64": _make_qr_b64(uri),
             "error": "Invalid code. Please scan the QR code and try again."},
            401,
        )

    user.mfa_enabled = True
    log_action(db, action="mfa_enabled", user_id=user.id, detail={"method": "totp_setup"}, ip=_ip(request))
    db.commit()

    new_token = create_session_token(user.id, mfa_ok=True)
    resp = RedirectResponse("/cases", status_code=302)
    _set_session_cookie(resp, new_token)
    return resp


# ── GET /logout ───────────────────────────────────────────────────────────────


@router.get("/logout", response_model=None)
def logout(request: Request, db: Session = Depends(get_db)) -> Response:
    sess = _session(request)
    if sess and sess.get("mfa"):
        log_action(db, action="logout", user_id=sess["uid"], ip=_ip(request))
        db.commit()
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("session")
    return resp
