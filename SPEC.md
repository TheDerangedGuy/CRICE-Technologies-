# CRICE Lab: SPEC.md (Milestone 1: Hardened DAG Skeleton)

CRICE = Cyber Reconnaissance & Intelligence Correlation Engine. The lab is a credential-login web app where operators move **cases** through an auditable, deterministic Directed Acyclic Graph (DAG) workflow with human compliance gates, bilateral separation of duties, and audited rework/recall loops.

This spec covers Milestone 1 only. Do not build anything listed under "Out of scope."

---

## Principles (apply to every milestone)
1. **Real Data End-to-End**: Every screen works with real database records. No dummy or non-functional UI buttons.
2. **Deterministic Operator Guidance**: The system displays a plain-language "NEXT ACTION" banner on each stage view. One primary action button per screen for the authorized role. Empty states and errors state clearly what action is required.
3. **Strict Server-Side Enforcement**: All stage transition rules, role checks, rework justifications, and compliance gates are enforced inside atomic database transactions in the service layer, never only in client-side HTML/JS.
4. **Comprehensive, Immutable Auditability**: Every state change, access attempt, approval, denial, rework loop, and recall writes to an append-only `audit_log` table protected by a PostgreSQL trigger blocking `UPDATE` and `DELETE`. Denied attempts (`allowed = False`) are committed to the audit log even when an exception is raised to the caller.
5. **Bilateral Separation of Duties**: An operator who operates or creates a case can never act as its reviewer (`operator_id != reviewer_id`). This rule is enforced in both application code and via a database constraint.
6. **B2B Client Governance**: Cases cannot be drafted or advanced without a verified active client record (`client_kyc_verified = True`, `msa_signed = True`).

---

## Stack
- Python 3.12+ (tested on Python 3.14), FastAPI, Jinja2 templates + HTMX (no React).
- PostgreSQL 16+ (docker-compose for local), SQLAlchemy 2.x + Alembic migrations. SQLite with foreign keys enabled for test suite.
- Auth: Argon2id password hashing, TOTP MFA (`pyotp`) with Fernet-encrypted secrets at rest, TOTP replay protection, signed HttpOnly server-side session cookies, CSRF protection on all mutating endpoints.
- Tests: `pytest` with TestClient. Config via `.env` (never commit secrets).

---

## Repo Layout
```
crice/
  app/
    main.py
    config.py
    db.py
    models.py
    cli.py
    auth/        (login, mfa, sessions, roles, crypto)
    cases/       (routes, service.py = DAG state machine)
    audit/       (log writer, viewer)
    admin/       (user management)
    templates/   (base, auth, cases, admin, audit)
    static/      (style.css)
  migrations/    (alembic migrations with PostgreSQL immutability trigger)
  tests/         (test_auth.py, test_cases.py, test_audit.py, conftest.py)
  docs/SOP/      (operator standard operating procedures)
  docker-compose.yml
  README.md
  SPEC.md
  CRICE.md
  .env.example
  .gitignore
```

---

## Roles
- `operator`: creates cases, performs collection, extracts claims, conducts correlation, builds dossiers.
- `reviewer`: conducts independent review; cannot be the operator of the same case (`reviewer_id != operator_id`).
- `compliance_admin`: approves person-subject intake, assigns reviewers, releases dossiers, triggers recalls, manages users, views complete audit log.

---

## Data Model (M1)

### `users`
- `id`: integer PK
- `email`: varchar(254), unique index
- `full_name`: varchar(200)
- `password_hash`: varchar(200)
- `role`: varchar(30), check constraint in (`operator`, `reviewer`, `compliance_admin`)
- `totp_secret_enc`: text nullable (Fernet encrypted)
- `mfa_enabled`: boolean, default false
- `is_active`: boolean, default true
- `failed_logins`: integer, default 0
- `locked_until`: timestamp with time zone, nullable
- `created_at`: timestamp with time zone

### `sessions`
- `id`: integer PK
- `session_id`: varchar(64), unique index
- `user_id`: integer FK -> users.id
- `mfa_verified`: boolean, default false
- `csrf_token`: varchar(64)
- `last_active_at`: timestamp with time zone
- `created_at`: timestamp with time zone
- `revoked`: boolean, default false

### `totp_used`
- `id`: integer PK
- `user_id`: integer FK -> users.id
- `code`: varchar(6)
- `used_at`: timestamp with time zone
- Unique constraint: (`user_id`, `code`)

### `cases`
- `id`: integer PK
- `case_ref`: varchar(14), format `^CRICE-[0-9A-F]{8}$`, unique index
- `client_name`: varchar(200)
- `client_kyc_verified`: boolean, default false
- `msa_signed`: boolean, default false
- `purpose`: varchar(50), enum
- `subject_type`: varchar(20), check in (`company`, `person`)
- `subject_name`: varchar(200)
- `subject_identifier`: varchar(50), nullable (Company MCA CIN or Person DIN/ID)
- `stage`: varchar(30), check in valid 10-stage list
- `intake_approved`: boolean, default false
- `consent_verified`: boolean, default false
- `dossier_version`: integer, default 1
- `is_recalled`: boolean, default false
- `rework_reason`: text, nullable
- `operator_id`: integer FK -> users.id
- `reviewer_id`: integer nullable FK -> users.id
- `created_by`: integer FK -> users.id
- `created_at`: timestamp with time zone
- `updated_at`: timestamp with time zone
- Table Check: `reviewer_id IS NULL OR operator_id != reviewer_id`

### `audit_log` (Append-Only)
- `id`: integer PK
- `timestamp`: timestamp with time zone
- `user_id`: integer nullable FK -> users.id
- `case_id`: integer nullable FK -> cases.id
- `action`: varchar(100)
- `from_stage`: varchar(30), nullable
- `to_stage`: varchar(30), nullable
- `allowed`: boolean, default true
- `detail`: JSON nullable
- `ip`: varchar(45), nullable
- *Database trigger: blocks all UPDATE and DELETE operations.*

---

## Enums
- **`purpose`**: `corporate_due_diligence`, `litigation_support`, `vendor_verification`, `employee_screening_with_consent`, `fraud_investigation`.
- **`subject_type`**: `company`, `person`.
- **`CaseStage`**:
  1. `INTAKE_DRAFT`
  2. `COMPLIANCE_GATE`
  3. `COLLECT`
  4. `CLAIM_EXTRACTION`
  5. `CORRELATION_AND_SCORING`
  6. `INDEPENDENT_REVIEW`
  7. `BUILD_AND_QA`
  8. `RELEASE_GATE`
  9. `CLOSED`
  10. `RECALLED`

---

## Stage Rules & Transition Matrix (`app/cases/service.py`)

All stage transitions are processed through `transition_case(case, user, to_stage, db, ip, reason=None)`:

1. **`INTAKE_DRAFT` -> `COLLECT` (Auto-advance)**:
   - Permitted if `subject_type == 'company'` AND `purpose` in (`corporate_due_diligence`, `litigation_support`, `vendor_verification`) AND `client_kyc_verified == True` AND `msa_signed == True`.
   - `intake_approved` is set to `True`.
2. **`INTAKE_DRAFT` -> `COMPLIANCE_GATE`**:
   - Required if `subject_type == 'person'`, OR `purpose == 'fraud_investigation'`, OR `purpose == 'employee_screening_with_consent'`.
3. **`COMPLIANCE_GATE` -> `COLLECT`**:
   - `compliance_admin` only.
   - If `purpose == 'employee_screening_with_consent'`, requires `consent_verified == True`.
   - Sets `intake_approved = True`.
4. **M1 Pass-Through Stages (`COLLECT`, `CLAIM_EXTRACTION`, `CORRELATION_AND_SCORING`, `BUILD_AND_QA`)**:
   - In Milestone 1, stages 3, 4, 5, and 7 allow forward progression by the assigned operator or `compliance_admin` without backing records/claims rows.
5. **Entering & Completing `INDEPENDENT_REVIEW`**:
   - Entering requires `cases.reviewer_id IS NOT NULL` and `reviewer_id != operator_id`.
   - Forward advance (`INDEPENDENT_REVIEW` -> `BUILD_AND_QA`) is permitted **only** to the assigned reviewer (`reviewer_id == user.id`).
6. **Rework Loops (Backward Transitions)**:
   - `INDEPENDENT_REVIEW` -> `COLLECT` or `CORRELATION_AND_SCORING` (actor: assigned reviewer).
   - `RELEASE_GATE` -> `BUILD_AND_QA` or `INDEPENDENT_REVIEW` (actor: `compliance_admin`).
   - Every backward transition requires a mandatory `rework_reason` ($\ge 10$ characters).
7. **`RELEASE_GATE` -> `CLOSED`**:
   - `compliance_admin` only.
8. **Recall Transition (`CLOSED` -> `RECALLED` -> `COLLECT` or `INDEPENDENT_REVIEW`)**:
   - `compliance_admin` only.
   - Requires mandatory `rework_reason` ($\ge 10$ characters).
   - Sets `is_recalled = True` and increments `dossier_version` ($1 \rightarrow 2$).
9. **Audit Trail**:
   - Every transition attempt writes an `audit_log` row with `from_stage`, `to_stage`, and `allowed = True/False`.
   - Denied transitions commit the audit log before raising HTTP 400 or 403.

---

## Screens & UI Standards
- **Swiss-Modernist Visual Discipline**: Strictly monochrome/greys, high-contrast monospace metadata (`CRICE-XXXXXXXX`), zero decorative clutter.
- **Explicit Disambiguation Labels**: Clear distinction between **"Case Ref (CIN)"** and **"Company MCA CIN"**.
- **Next Action Banner**: Shows the current state and plain-language instructions on what is needed to advance.
- **Role-Gated Controls**: Action buttons are disabled or hidden when the viewing user is not authorized, with clear explanatory text (e.g., *"Awaiting Compliance Admin approval"* or *"Locked for Independent Review"*).
- **Rework & Recall Modals**: Clean forms with required reason fields.

---

## Acceptance Tests (pytest; all must pass)
1. Protected pages require full authenticated session with MFA.
2. Five failed logins trigger 15-minute account lockout.
3. Account lockout rejects subsequent attempts until window expires.
4. Correct password resets failed login counter.
5. Inactive users and pending-MFA sessions are rejected.
6. Generic error message on bad credentials prevents user enumeration.
7. CSRF tokens enforced on state-changing requests.
8. TOTP replay protection prevents code reuse.
9. Session revocation on logout invalidates cookie immediately.
10. `case_ref` is unique and matches `^CRICE-[0-9A-F]{8}$`.
11. Company intake with valid KYC/MSA auto-advances to `COLLECT`.
12. Person intake halts at `COMPLIANCE_GATE` and blocks operator advance.
13. `employee_screening_with_consent` halts until `consent_verified = True`.
14. Stage skipping is blocked and logged as `allowed = False` in `audit_log`.
15. `operator_id != reviewer_id` enforced in DB constraint and service layer.
16. Non-assigned users cannot advance `INDEPENDENT_REVIEW`.
17. Reviewer rework requires reason $\ge 10$ chars and moves case backward.
18. Operator cannot close case; only `compliance_admin` can advance `RELEASE_GATE` -> `CLOSED`.
19. `compliance_admin` can recall a closed case, which increments `dossier_version` and sets `is_recalled = True`.
20. Audit log trigger prevents `UPDATE` and `DELETE` at the database level.
21. Every successful and denied transition writes an `audit_log` row.

---

## Out of Scope for M1
Live source collection, evidence blob storage, LLM API calls, atomic claims table, dossier PDF generation, secure delivery links, file uploads, web scraping.
