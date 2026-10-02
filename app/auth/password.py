"""
app/auth/password.py – argon2 password hashing.
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

_ph = PasswordHasher()


def hash_password(plaintext: str) -> str:
    """Hash a password with argon2id."""
    return _ph.hash(plaintext)


def verify_password(stored_hash: str, plaintext: str) -> bool:
    """Return True if plaintext matches stored_hash; False otherwise."""
    try:
        _ph.verify(stored_hash, plaintext)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
