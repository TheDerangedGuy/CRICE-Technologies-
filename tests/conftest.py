"""
tests/conftest.py – pytest configuration and shared fixtures.

IMPORTANT: env vars must be set BEFORE any app module is imported,
because app/config.py reads them at import time (after load_dotenv()).
"""
import os

# ── Inject test environment FIRST ────────────────────────────────────────────
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_crice.db")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production-32ch!")
os.environ.setdefault("CSRF_SECRET", "test-csrf-secret-not-for-production-32!")
os.environ.setdefault("SECURE_COOKIES", "false")

# Phase-1: only import what exists so far.
# Full fixtures (db, client, helpers) are added in Phase 2 alongside auth modules.
