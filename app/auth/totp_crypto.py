"""
app/auth/totp_crypto.py – Fernet-based encryption for TOTP secrets at rest.

TOTP_ENCRYPTION_KEY must be a URL-safe base64-encoded 32-byte Fernet key.
Generate one with:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

In tests, a deterministic test key is used (set in conftest.py before any import).
"""
from cryptography.fernet import Fernet, InvalidToken

import app.config as config


def _fernet() -> Fernet:
    key = config.TOTP_ENCRYPTION_KEY
    if not key:
        raise RuntimeError(
            "TOTP_ENCRYPTION_KEY is not set. "
            "Generate one and add it to your .env file."
        )
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_totp_secret(plaintext: str) -> str:
    """Encrypt a TOTP base32 secret and return the Fernet ciphertext as a string."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_totp_secret(ciphertext: str) -> str:
    """Decrypt a Fernet ciphertext back to the TOTP base32 secret."""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Failed to decrypt TOTP secret – key mismatch or corrupted data") from exc
