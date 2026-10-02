# CRICE Lab: SPEC.md (Milestone 1: Skeleton)

CRICE = Cyber Reconnaissance & Intelligence Correlation Engine. The lab is a credential-login web app where operators move **cases** through a fixed 7-stage workflow with human gates. This spec covers Milestone 1 only. Do not build anything listed under "Out of scope."

## Principles (apply to every milestone)
1. Every screen works end to end with real data. No dummy buttons.
2. The system tells the operator the next action. One primary button per screen; plain-language labels; empty states and errors say what to do.
3. Stage rules are enforced **server-side**, never only in the UI.
4. Every state change writes to the audit log.
5. Development uses demo data only (listed companies, own entity). No real client or private-individual data.

## Stack
- Python 3.12, FastAPI, Jinja2 templates + HTMX (no React).
- PostgreSQL (docker-compose for local), SQLAlchemy 2.x + Alembic migrations.
- Auth: argon2 password hashing, TOTP MFA (pyotp), signed HttpOnly session cookies, CSRF protection.
- Tests: pytest. Config via `.env` (provide `.env.example`; never commit secrets).

## Repo layout
```
crice/
  app/
    main.py
    config.py
    db.py
    models.py
    auth/        (login, mfa, sessions, roles)
    cases/       (routes, service.py = ALL stage logic)
    audit/       (log writer, viewer)
    admin/       (user management)
    templates/
    static/
  migrations/
  tests/
  docs/SOP/      (one page per stage; written by the founder)
  docker-compose.yml
  README.md
  SPEC.md
  .env.example
  .gitignore
```

## Roles
- `operator`: creates and works cases.
- `reviewer`: reviews work; cannot be the case's operator for the same case.
- `compliance_admin`: approves person-subject intake, manages users, releases dossiers, views full audit log.

## Data model (M1)
**users**: id, email (unique), full_name, password_hash, role, totp_secret, mfa_enabled, is_active, failed_logins, locked_until, created_at.

**cases**: id, case_ref (format `CRICE-` + 8 uppercase hex, unique), client_name, purpose (enum), subject_type (`company` | `person`), subject_name, subject_identifier (CIN or DIN, optional), stage (enum), intake_approved (bool, default false), operator_id, created_by, created_at, updated_at.

**audit_log** (append-only): id, timestamp, user_id, case_id (nullable), action, detail (JSON), ip. No update or delete code paths exist for this table.

**Enums**
- `purpose`: corporate_due_diligence, litigation_support, vendor_verification, employee_screening_with_consent, fraud_investigation.
- `stage`: INTAKE, COLLECT, PRE_AI_REVIEW, AI_PROCESSING, POST_AI_REVIEW, BUILD, RELEASE, CLOSED.

## Stage rules (single function `advance_case(case, user, to_stage)` in `cases/service.py`)
- Only forward by one step. No skipping. No going back in M1.
- INTAKE → COLLECT: requires `intake_approved = true`. Company subjects are auto-approved. Person subjects require approval by `compliance_admin`.
- Other transitions in M1: the assigned operator may advance; each writes an audit entry. (Real gates arrive in later milestones.)
- RELEASE → CLOSED: `compliance_admin` only.
- Any rule violation returns a clear message ("This case needs compliance approval before collection can start.") and writes a `denied` audit entry.

## Screens
1. **Login** (email, password, then TOTP). Lockout after 5 failed attempts for 15 minutes.
2. **Case list**: queue grouped by stage, showing case_ref, subject, client, stage, operator. Primary button: "New case". Empty state: "No cases yet. Click New case to start."
3. **New case (Intake)**: fields above; purpose is a dropdown; plain-language help text under each field.
4. **Case workspace**: stage bar across the top (current stage highlighted), case summary, one primary action button for the current stage, and a case-scoped activity feed.
5. **Admin** (compliance_admin): create users, set role, deactivate, reset MFA.
6. **Audit viewer** (compliance_admin): filter by case, user, action; export CSV.

## Seeding and first run
- `python -m app.cli create-admin` creates the first compliance_admin interactively. **No default passwords anywhere.**
- `python -m app.cli seed-demo` creates 2 demo cases (a listed company and the CRICE entity) so the app is usable on first run.
- README must document: clone, `.env`, `docker compose up -d`, migrate, create-admin, run.

## Acceptance tests (pytest; all must pass)
1. A user cannot reach any page without logging in and passing MFA.
2. Five failed logins lock the account.
3. A case cannot skip a stage.
4. A person-subject case cannot leave INTAKE until compliance approves.
5. An operator cannot close a case; only compliance_admin can.
6. Every successful and denied transition creates an audit entry.
7. Audit entries cannot be modified or deleted through any route.
8. A reviewer cannot be set as reviewer on a case they operate.
9. `case_ref` is unique and matches the `CRICE-XXXXXXXX` format.

## Definition of done
A non-builder reads `docs/SOP/00-quickstart.md`, logs in, creates a case, and walks it from INTAKE to CLOSED using only the SOP, and every action appears in the audit log.

## Out of scope for M1 (do not build)
Source collection, evidence storage, AI calls, claims, dossier PDF, secure delivery links, file uploads, any scraping, email sending.

## Instruction to the build agent
Build against this spec only. Work in small commits. Run the tests after each task. If anything in the spec is ambiguous, stop and list the question instead of guessing. Do not add features, libraries, or screens that aren't listed.
