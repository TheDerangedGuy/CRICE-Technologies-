# CRICE Lab: Cyber Reconnaissance & Intelligence Correlation Engine

**Milestone 1: Hardened DAG Skeleton**

CRICE is an intelligence correlation web application where operators move cases through an auditable, deterministic Directed Acyclic Graph (DAG) state machine with human compliance gates, bilateral separation of duties, and audited rework/recall loops.

---

## Architecture & Principles

1. **Deterministic 10-State DAG**:
   - `INTAKE_DRAFT` $\rightarrow$ `COMPLIANCE_GATE` $\rightarrow$ `COLLECT` $\rightarrow$ `CLAIM_EXTRACTION` $\rightarrow$ `CORRELATION_AND_SCORING` $\rightarrow$ `INDEPENDENT_REVIEW` $\rightarrow$ `BUILD_AND_QA` $\rightarrow$ `RELEASE_GATE` $\rightarrow$ `CLOSED` (with `RECALLED` loop).
   - Auto-advance to `COLLECT` only for company subjects with approved purposes under verified B2B client KYC & MSA.
   - Person subjects, employee screening, and fraud investigations strictly require `compliance_admin` review.
2. **Bilateral Separation of Duties**:
   - Case operator cannot review their own case (`operator_id != reviewer_id`), enforced via database table check constraints and service-layer validation.
   - Assigned reviewers cannot advance operator workflow stages (`COLLECT`, `CLAIM_EXTRACTION`, etc.), and case operators cannot advance or approve `INDEPENDENT_REVIEW`.
3. **Audit Log Immutability**:
   - Append-only `audit_log` records every transition attempt (both allowed and denied).
   - Database-level triggers block all `UPDATE` and `DELETE` operations on `audit_log`.
4. **Security-Hardened Authentication**:
   - Argon2id password hashing with account lockout after 5 failed attempts (15-minute window).
   - TOTP MFA (`pyotp`) with Fernet-encrypted secret storage and replay prevention.
   - Server-side sessions with cryptographic CSRF token enforcement on all mutating routes.

---

## Technology Stack

- **Backend**: Python 3.12+ (tested on Python 3.14), FastAPI, Jinja2 templates + HTMX.
- **Database**: PostgreSQL 16+ (production & docker-compose) / SQLite with trigger parity (automated test suite), SQLAlchemy 2.x, Alembic.
- **Security**: Argon2, cryptography (Fernet), pyotp.
- **Testing**: pytest, Starlette TestClient.

---

## Repository Structure

```
CRICE-Technologies-/
├── app/
│   ├── admin/          # Compliance admin user management routes
│   ├── audit/          # Append-only audit logger and viewer
│   ├── auth/           # Login, TOTP MFA, sessions, crypto, lockout
│   ├── cases/          # 10-state DAG state machine, transition validation
│   ├── templates/      # Jinja2 templates (monochrome Swiss-modernist UI)
│   ├── static/         # CSS styles
│   ├── cli.py          # Administrative CLI (create-admin, seed-demo)
│   ├── config.py       # Pydantic environment configuration
│   ├── db.py           # Database engine and sessionmaker
│   ├── models.py       # SQLAlchemy ORM models and schema constraints
│   └── main.py         # FastAPI application entry point
├── docs/
│   └── SOP/            # Standard Operating Procedures for operators
├── migrations/         # Alembic database migrations (with PL/pgSQL triggers)
├── tests/              # Test suite (43 acceptance & security tests)
├── docker-compose.yml  # Local PostgreSQL container specification
├── requirements.txt    # Pinned dependency requirements
├── SPEC.md             # Milestone 1 technical specification
├── CRICE.md            # System architecture and design principles
└── README.md           # Project documentation
```

---

## Setup & Running Locally

### 1. Environment Setup

Create and activate a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Create `.env` from template:
```bash
cp .env.example .env
```

Ensure `CRICE_DATABASE_URL`, `CRICE_SESSION_SECRET`, and `CRICE_TOTP_KEY` are configured.

### 2. Database Migrations

Apply Alembic migrations to create tables and database triggers:
```bash
alembic upgrade head
```

### 3. CLI Management

Create a Compliance Administrator user:
```bash
python -m app.cli create-admin --email admin@crice.demo --name "Admin Demo" --password "AdminPass123!@#"
```

Seed initial demo data (idempotent; seeds 3 users and 2 demo cases):
```bash
python -m app.cli seed-demo
```

### 4. Running the Web Application

Start the development server with Uvicorn:
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Navigate to `http://localhost:8000` to log in.

---

## Running Acceptance Tests

Run the full automated test suite (all 43 tests):
```bash
pytest tests/ -v
```