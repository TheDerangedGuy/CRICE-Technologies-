"""
app/auth/routes.py – login, MFA, and logout routes.

Security hardening per approved plan:
  - Generic error messages (no user enumeration)
  - TOTP replay protection (totp_used table)
  - Encrypted TOTP secrets (Fernet)
  - Server-side sessions (opaque cookie ← session_id only)
  - CSRF token checked on every state-changing POST
  - Pending-MFA sessions grant no access to protected routes
"""
import datetime
import io
import base64
from typing import Optional

import pyotp
import qrcode
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

import app.config as config
from app.audit.writer import log_action
from app.auth.password import verify_password
from app.auth.sessions import (
    COOKIE_NAME,
    create_session,
    load_session,
    promote_to_mfa,
    revoke_session,
    set_session_cookie,
    clear_session_cookie,
)
from app.auth.totp_crypto import encrypt_totp_secret, decrypt_totp_secret
from app.db import get_db
from app.models import Session as SessionModel, TotpUsed, User
from app.templates_config import templates

router = APIRouter(tags=["auth"])

_LOCKOUT_ATTEMPTS = config.LOCKOUT_ATTEMPTS
_LOCKOUT_DURATION = datetime.timedelta(minutes=config.LOCKOUT_MINUTES)
_GENERIC_LOGIN_ERROR = "Invalid email or password."


# ── Internal helpers ──────────────────────────────────────────────────────────


def _ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _get_sess(request: Request, db: Session) -> Optional[SessionModel]:
    """Load the current session row from the DI DB session."""
    sid: Optional[str] = getattr(request.state, "session_id", None)
    return load_session(db, sid)


def _render(
    request: Request,
    template: str,
    ctx: dict,
    status: int = 200,
    sess: Optional[SessionModel] = None,
) -> HTMLResponse:
    ctx.setdefault("request", request)
    ctx.setdefault("current_user", None)
    ctx.setdefault("csrf_token", sess.csrf_token if sess else "")
    return templates.TemplateResponse(template, ctx, status_code=status)


def _csrf_ok(sess: Optional[SessionModel], submitted: str) -> bool:
    return bool(sess and submitted == sess.csrf_token)


def _make_qr_b64(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def _record_totp_use(db: Session, user_id: int, code: str) -> bool:
    """Return True if the code is fresh; False if replayed. Prunes old entries."""
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(seconds=90)
    db.query(TotpUsed).filter(
        TotpUsed.user_id == user_id, TotpUsed.used_at < cutoff
    ).delete()
    try:
        db.add(TotpUsed(user_id=user_id, code=code, used_at=now))
        db.flush()
        return True
    except IntegrityError:
        db.rollback()
        return False


# ── GET /login ────────────────────────────────────────────────────────────────


@router.get("/login", response_model=None)
def login_get(request: Request, db: Session = Depends(get_db)) -> Response:
    sess = _get_sess(request, db)
    if sess:
        if sess.mfa_verified:
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

    def _bad() -> Response:
        return _render(request, "auth/login.html", {"error": _GENERIC_LOGIN_ERROR}, 401)

    user: Optional[User] = (
        db.query(User).filter(User.email == email.strip().lower()).first()
    )
    if not user or not user.is_active:
        return _bad()

    # Lockout check
    if user.locked_until:
        lu = user.locked_until
        if lu.tzinfo is None:
            lu = lu.replace(tzinfo=datetime.timezone.utc)
        if lu > now:
            mins = max(1, int((lu - now).total_seconds() / 60) + 1)
            return _render(request, "auth/login.html",
                           {"error": f"Account locked. Try again in {mins} minute(s)."}, 401)

    # Password check
    if not verify_password(user.password_hash, password):
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= _LOCKOUT_ATTEMPTS:
            user.locked_until = now + _LOCKOUT_DURATION
            db.flush()
            log_action(db, action="account_locked", user_id=user.id,
                       detail={"reason": "Too many failed login attempts"}, ip=ip)
        db.commit()
        return _bad()

    # Password OK
    user.failed_logins = 0
    user.locked_until = None
    db.flush()

    session_id, _csrf = create_session(db, user.id, mfa_verified=False)
    dest = "/mfa" if user.mfa_enabled else "/mfa/setup"
    resp = RedirectResponse(dest, status_code=302)
    set_session_cookie(resp, session_id)
    return resp


# ── GET /mfa ──────────────────────────────────────────────────────────────────


@router.get("/mfa", response_model=None)
def mfa_get(request: Request, db: Session = Depends(get_db)) -> Response:
    sess = _get_sess(request, db)
    if not sess:
        return RedirectResponse("/login", status_code=302)
    if sess.mfa_verified:
        return RedirectResponse("/cases", status_code=302)
    user: Optional[User] = db.get(User, sess.user_id)
    if not user or not user.mfa_enabled:
        return RedirectResponse("/mfa/setup", status_code=302)
    return _render(request, "auth/mfa.html", {"error": None}, sess=sess)


# ── POST /mfa ─────────────────────────────────────────────────────────────────


@router.post("/mfa", response_model=None)
async def mfa_post(
    request: Request,
    totp_code: str = Form(...),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
) -> Response:
    sess = _get_sess(request, db)
    if not sess or sess.mfa_verified:
        return RedirectResponse("/login", status_code=302)

    if not _csrf_ok(sess, csrf_token):
        return _render(request, "auth/mfa.html",
                       {"error": "Security check failed. Please try again."}, 403, sess=sess)

    user: Optional[User] = db.get(User, sess.user_id)
    if not user or not user.totp_secret_enc:
        return RedirectResponse("/login", status_code=302)

    plain = decrypt_totp_secret(user.totp_secret_enc)
    totp = pyotp.TOTP(plain)
    code = totp_code.strip()

    if not totp.verify(code, valid_window=1):
        log_action(db, action="mfa_failed", user_id=user.id, ip=_ip(request))
        db.commit()
        return _render(request, "auth/mfa.html", {"error": "Invalid code. Please try again."}, 401, sess=sess)

    if not _record_totp_use(db, user.id, code):
        return _render(request, "auth/mfa.html",
                       {"error": "Code already used. Please wait for the next code."}, 401, sess=sess)

    promote_to_mfa(db, sess)
    log_action(db, action="login", user_id=user.id, detail={"method": "totp"}, ip=_ip(request))
    db.commit()
    return RedirectResponse("/cases", status_code=302)


# ── GET /mfa/setup ────────────────────────────────────────────────────────────


@router.get("/mfa/setup", response_model=None)
def mfa_setup_get(request: Request, db: Session = Depends(get_db)) -> Response:
    sess = _get_sess(request, db)
    if not sess:
        return RedirectResponse("/login", status_code=302)
    if sess.mfa_verified:
        return RedirectResponse("/cases", status_code=302)
    user: Optional[User] = db.get(User, sess.user_id)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if user.mfa_enabled:
        return RedirectResponse("/mfa", status_code=302)

    if not user.totp_secret_enc:
        plain = pyotp.random_base32()
        user.totp_secret_enc = encrypt_totp_secret(plain)
        db.commit()
    else:
        plain = decrypt_totp_secret(user.totp_secret_enc)

    uri = pyotp.TOTP(plain).provisioning_uri(name=user.email, issuer_name="CRICE Lab")
    return _render(request, "auth/mfa_setup.html",
                   {"totp_uri": uri, "qr_b64": _make_qr_b64(uri), "error": None}, sess=sess)


# ── POST /mfa/setup ───────────────────────────────────────────────────────────


@router.post("/mfa/setup", response_model=None)
async def mfa_setup_post(
    request: Request,
    totp_code: str = Form(...),
    csrf_token: str = Form(default="", alias="_csrf"),
    db: Session = Depends(get_db),
) -> Response:
    sess = _get_sess(request, db)
    if not sess or sess.mfa_verified:
        return RedirectResponse("/login", status_code=302)

    if not _csrf_ok(sess, csrf_token):
        return RedirectResponse("/mfa/setup", status_code=302)

    user: Optional[User] = db.get(User, sess.user_id)
    if not user or not user.totp_secret_enc:
        return RedirectResponse("/login", status_code=302)

    plain = decrypt_totp_secret(user.totp_secret_enc)
    totp = pyotp.TOTP(plain)
    code = totp_code.strip()

    if not totp.verify(code, valid_window=1):
        uri = totp.provisioning_uri(name=user.email, issuer_name="CRICE Lab")
        return _render(request, "auth/mfa_setup.html",
                       {"totp_uri": uri, "qr_b64": _make_qr_b64(uri),
                        "error": "Invalid code. Please scan the QR code and try again."}, 401, sess=sess)

    if not _record_totp_use(db, user.id, code):
        uri = pyotp.TOTP(plain).provisioning_uri(name=user.email, issuer_name="CRICE Lab")
        return _render(request, "auth/mfa_setup.html",
                       {"totp_uri": uri, "qr_b64": _make_qr_b64(uri),
                        "error": "Code already used. Please wait for the next code."}, 401, sess=sess)

    user.mfa_enabled = True
    db.flush()
    promote_to_mfa(db, sess)
    log_action(db, action="mfa_enabled", user_id=user.id,
               detail={"method": "totp_setup"}, ip=_ip(request))
    db.commit()
    return RedirectResponse("/cases", status_code=302)


# ── GET /logout ───────────────────────────────────────────────────────────────


@router.get("/logout", response_model=None)
def logout(request: Request, db: Session = Depends(get_db)) -> Response:
    sess = _get_sess(request, db)
    if sess:
        if sess.mfa_verified:
            log_action(db, action="logout", user_id=sess.user_id, ip=_ip(request))
        revoke_session(db, sess)

    resp = RedirectResponse("/login", status_code=302)
    clear_session_cookie(resp)
    return resp
