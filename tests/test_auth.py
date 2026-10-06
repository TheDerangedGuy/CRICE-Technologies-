"""
tests/test_auth.py – acceptance tests 1 and 2.

Test 1: A user cannot reach any page without logging in and passing MFA.
Test 2: Five failed logins lock the account.
Additional: pending-MFA sessions rejected, deactivated-user sessions rejected,
            CSRF enforcement, TOTP replay protection.
"""
import datetime

import pyotp
import pytest

from app.models import User, UserRole, Session as SessionModel
from tests.conftest import (
    csrf_token_for,
    make_user,
    make_session,
)


# ── Test 1: protected pages require full MFA session ─────────────────────────

class TestProtectedRoutes:
    """Spec acceptance test 1: no page reachable without login + MFA."""

    PROTECTED_URLS = [
        "/cases",
        "/cases/new",
    ]

    def test_unauthenticated_redirects_to_login(self, client):
        for url in self.PROTECTED_URLS:
            r = client.get(url, follow_redirects=False)
            assert r.status_code == 302, f"{url} did not redirect unauthenticated user"
            assert r.headers["location"].endswith("/login"), (
                f"{url} redirected to {r.headers['location']!r}, expected /login"
            )

    def test_partial_session_mfa_not_done_is_rejected(self, client, db):
        """Pending-MFA session (mfa_verified=False) is rejected for protected routes."""
        user = make_user(db)
        _row, cookies = make_session(db, user, mfa_verified=False)
        r = client.get("/cases", cookies=cookies, follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["location"]

    def test_full_session_reaches_cases(self, client, db):
        """A fully authenticated session (password + MFA) reaches /cases."""
        user = make_user(db)
        _row, cookies = make_session(db, user, mfa_verified=True)
        r = client.get("/cases", cookies=cookies, follow_redirects=False)
        assert r.status_code == 200

    def test_login_page_accessible_without_session(self, client):
        r = client.get("/login")
        assert r.status_code == 200
        assert "Sign in" in r.text

    def test_deactivated_user_session_is_rejected(self, client, db):
        """Sessions belonging to deactivated users must be rejected."""
        user = make_user(db)
        _row, cookies = make_session(db, user, mfa_verified=True)

        # Deactivate the user after session was created
        user.is_active = False
        db.commit()

        r = client.get("/cases", cookies=cookies, follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["location"]


# ── Test 2: five failed logins lock the account ───────────────────────────────

class TestLoginLockout:
    """Spec acceptance test 2: 5 failed attempts → 15-minute lockout."""

    def test_five_bad_passwords_lock_account(self, client, db):
        user = make_user(db, email="lockme@crice.test", password="CorrectPassword!Long1")

        for i in range(5):
            r = client.post("/login", data={
                "email": "lockme@crice.test",
                "password": "WrongPassword!",
            })
            assert r.status_code in (200, 401), f"Unexpected status on attempt {i+1}"

        db.refresh(user)
        assert user.locked_until is not None, "locked_until should be set after 5 bad attempts"
        assert user.failed_logins >= 5

    def test_locked_account_shows_lockout_message(self, client, db):
        user = make_user(db, email="locked@crice.test", password="CorrectPassword!Long1")

        for _ in range(5):
            client.post("/login", data={"email": "locked@crice.test", "password": "Bad!"})

        # 6th attempt with correct password – still rejected
        r = client.post("/login", data={
            "email": "locked@crice.test",
            "password": "CorrectPassword!Long1",
        })
        assert "locked" in r.text.lower()

    def test_correct_password_resets_failed_counter(self, client, db):
        """A successful login clears the failed_logins counter."""
        user = make_user(
            db,
            email="almost@crice.test",
            password="CorrectPassword!Long1",
            mfa_enabled=False,
        )
        # Give them a TOTP secret even without mfa_enabled so setup page works
        from app.auth.totp_crypto import encrypt_totp_secret
        user.totp_secret_enc = encrypt_totp_secret(pyotp.random_base32())
        db.commit()

        for _ in range(4):
            client.post("/login", data={"email": "almost@crice.test", "password": "Bad!"})

        db.refresh(user)
        assert user.failed_logins == 4

        client.post("/login", data={"email": "almost@crice.test", "password": "CorrectPassword!Long1"})

        db.refresh(user)
        assert user.failed_logins == 0
        assert user.locked_until is None

    def test_inactive_user_cannot_login(self, client, db):
        make_user(db, email="inactive@crice.test", password="Password1!TestLong", is_active=False)
        r = client.post("/login", data={"email": "inactive@crice.test", "password": "Password1!TestLong"})
        # Generic error (no user enumeration)
        assert r.status_code in (200, 401)
        assert "invalid" in r.text.lower()

    def test_generic_error_for_nonexistent_user(self, client, db):
        """Login with unknown email must return same generic error as wrong password."""
        r = client.post("/login", data={
            "email": "nobody@crice.test",
            "password": "SomePassword1!Long",
        })
        assert r.status_code in (200, 401)
        assert "invalid" in r.text.lower()


# ── CSRF protection ───────────────────────────────────────────────────────────

class TestCSRF:
    def test_mfa_post_rejects_bad_csrf(self, client, db):
        """POST /mfa with a wrong _csrf token must be rejected."""
        user = make_user(db)
        _row, cookies = make_session(db, user, mfa_verified=False)
        r = client.post(
            "/mfa",
            data={"totp_code": "000000", "_csrf": "totally-wrong"},
            cookies=cookies,
        )
        assert r.status_code in (403, 200)
        assert "security check" in r.text.lower() or r.status_code == 403


# ── TOTP replay protection ────────────────────────────────────────────────────

class TestTOTPReplay:
    def test_totp_code_cannot_be_reused(self, client, db):
        """The same TOTP code submitted twice must be rejected on the second attempt."""
        user = make_user(db)
        # Use the plaintext stored by make_user on the object
        db.refresh(user)
        from app.auth.totp_crypto import decrypt_totp_secret
        plain = decrypt_totp_secret(user.totp_secret_enc)
        totp = pyotp.TOTP(plain)
        code = totp.now()

        # First use (pending session)
        _row1, cookies1 = make_session(db, user, mfa_verified=False)
        csrf = _row1.csrf_token

        r1 = client.post("/mfa", data={"totp_code": code, "_csrf": csrf},
                          cookies=cookies1, follow_redirects=False)
        # First use should succeed (redirects to /cases)
        assert r1.status_code == 302, f"First MFA use failed: {r1.text[:200]}"

        # Second use with the same code in a new pending session
        _row2, cookies2 = make_session(db, user, mfa_verified=False)
        csrf2 = _row2.csrf_token
        r2 = client.post("/mfa", data={"totp_code": code, "_csrf": csrf2},
                         cookies=cookies2, follow_redirects=False)
        # Should be rejected as replay
        assert r2.status_code in (200, 401), f"Replay was not rejected: {r2.status_code}"
        assert "already used" in r2.text.lower() or r2.status_code == 401



# ── Session revocation ────────────────────────────────────────────────────────

class TestSessionRevocation:
    def test_logout_revokes_session(self, client, db):
        """After logout, the session cookie no longer grants access."""
        user = make_user(db)
        _row, cookies = make_session(db, user, mfa_verified=True)

        # Verify access before logout
        r1 = client.get("/cases", cookies=cookies)
        assert r1.status_code == 200

        # Logout
        client.get("/logout", cookies=cookies)

        # Session should now be revoked
        db.refresh(_row)
        assert _row.revoked is True
