"""
app/config.py – centralised configuration loaded from environment / .env file.
"""
import os
from dotenv import load_dotenv

load_dotenv()  # loads .env if present; env vars already set take priority

DATABASE_URL: str = os.environ.get("DATABASE_URL", "")
SECRET_KEY: str = os.environ.get("SECRET_KEY", "")
CSRF_SECRET: str = os.environ.get("CSRF_SECRET", "")
SESSION_MAX_AGE: int = int(os.environ.get("SESSION_MAX_AGE", "86400"))
SECURE_COOKIES: bool = os.environ.get("SECURE_COOKIES", "false").lower() == "true"

# Lockout policy (auth/routes.py uses these constants)
LOCKOUT_ATTEMPTS: int = 5
LOCKOUT_MINUTES: int = 15
