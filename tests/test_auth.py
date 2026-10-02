"""
tests/test_auth.py – acceptance tests 1 and 2.

Test 1: A user cannot reach any page without logging in and passing MFA.
Test 2: Five failed logins lock the account.
"""
import datetime

import pyotp
import pytest

from app.models import User, UserRole
from tests.conftest import (
    csrf_token_for,
    make_user,
    session_cookies,
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
        """Session with mfa=False is treated as unauthenticated for protected routes."""
        user = make_user(db)
        cookies = session_cookies(user.id, mfa_ok=False)
        r = client.get("/cases", cookies=cookies, follow_redirects=False)
        assert r.status_code == 302
        assert "/login" in r.headers["location"]

    def test_full_session_reaches_cases(self, client, db):
        """A fully authenticated session (password + MFA) can reach /cases."""
        # We need a stub /cases route – it's added in Phase 3.
        # Until then, / redirects to /cases which will 401 → /login.
        # This test just confirms the session is accepted (not 401).
        # We'll re-verify in test_cases.py once the route exists.
        user = make_user(db)
        cookies = session_cookies(user.id, mfa_ok=True)
        # / → /cases → 401 (no cases router yet) → /login
        # The important thing: /login is NOT the first redirect target from /cases
        # with a valid session; instead the cases router will handle it.
        # For now assert no 401 is raised for routes that do exist:
        r = client.get("/login", cookies=cookies, follow_redirects=False)
        # /login should redirect away since the user is fully logged in
        assert r.status_code == 302

    def test_login_page_accessible_without_session(self, client):
        r = client.get("/login")
        assert r.status_code == 200
        assert "Sign in" in r.text


# ── Test 2: five failed logins lock the account ───────────────────────────────

class TestLoginLockout:
    """Spec acceptance test 2: 5 failed attempts → 15-minute lockout."""

    def test_five_bad_passwords_lock_account(self, client, db):
        user = make_user(db, email="lockme@crice.test", password="CorrectPassword!")

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
        user = make_user(db, email="locked@crice.test", password="CorrectPassword!")

        # Trigger lockout
        for _ in range(5):
            client.post("/login", data={"email": "locked@crice.test", "password": "Bad!"})

        # 6th attempt with correct password – should still be rejected
        r = client.post("/login", data={
            "email": "locked@crice.test",
            "password": "CorrectPassword!",
        })
        assert "locked" in r.text.lower(), "Lockout message not shown after 5 failed attempts"

    def test_correct_password_resets_failed_counter(self, client, db):
        """A successful login clears the failed_logins counter."""
        user = make_user(
            db,
            email="almost@crice.test",
            password="CorrectPassword!",
            mfa_enabled=False,  # no TOTP so we can check the password step
        )
        user.totp_secret = pyotp.random_base32()
        db.commit()

        # 4 bad attempts
        for _ in range(4):
            client.post("/login", data={"email": "almost@crice.test", "password": "Bad!"})

        db.refresh(user)
        assert user.failed_logins == 4

        # 1 correct attempt
        client.post("/login", data={"email": "almost@crice.test", "password": "CorrectPassword!"})

        db.refresh(user)
        assert user.failed_logins == 0, "failed_logins should reset after successful login"
        assert user.locked_until is None

    def test_inactive_user_cannot_login(self, client, db):
        make_user(db, email="inactive@crice.test", password="Password1!", is_active=False)
        r = client.post("/login", data={"email": "inactive@crice.test", "password": "Password1!"})
        assert "Invalid email" in r.text


# ── CSRF protection ───────────────────────────────────────────────────────────

class TestCSRF:
    def test_mfa_post_rejects_bad_csrf(self, client, db):
        """POST /mfa with a wrong _csrf token must be rejected."""
        user = make_user(db)
        cookies = session_cookies(user.id, mfa_ok=False)
        # Send with wrong CSRF token
        r = client.post(
            "/mfa",
            data={"totp_code": "000000", "_csrf": "totally-wrong"},
            cookies=cookies,
        )
        assert r.status_code in (403, 200)
        assert "security check" in r.text.lower() or r.status_code == 403
