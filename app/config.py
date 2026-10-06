"""
app/config.py – centralised configuration loaded from environment / .env file.
"""
import os
from dotenv import load_dotenv

load_dotenv()  # loads .env if present; env vars already set take priority

DATABASE_URL: str = os.environ.get("DATABASE_URL", "")
SECRET_KEY: str = os.environ.get("SECRET_KEY", "")
# 32-byte Fernet key (base64-urlsafe) for encrypting TOTP secrets at rest.
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
TOTP_ENCRYPTION_KEY: str = os.environ.get("TOTP_ENCRYPTION_KEY", "")
SECURE_COOKIES: bool = os.environ.get("SECURE_COOKIES", "false").lower() == "true"

# Session timeouts
SESSION_IDLE_SECONDS: int = int(os.environ.get("SESSION_IDLE_SECONDS", str(8 * 3600)))    # 8 h
SESSION_ABSOLUTE_SECONDS: int = int(os.environ.get("SESSION_ABSOLUTE_SECONDS", str(24 * 3600)))  # 24 h

# Lockout policy
LOCKOUT_ATTEMPTS: int = 5
LOCKOUT_MINUTES: int = 15

# Password minimum length
PASSWORD_MIN_LENGTH: int = 12
