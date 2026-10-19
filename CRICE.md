# CRICE: Cyber Reconnaissance & Intelligence Correlation Engine
## Architecture, Workflow, and State-Machine Specification (Master Document)

---

## 1. Executive Summary & Vision

**CRICE** (Cyber Reconnaissance & Intelligence Correlation Engine) is an enterprise-grade cyber reconnaissance and corporate intelligence correlation platform designed for high-stakes compliance, litigation support, fraud investigation, and due diligence operations.

CRICE transitions investigation workflows away from unstructured, error-prone manual notes toward an **auditable, deterministic Directed Acyclic Graph (DAG) State Machine** with human gates, bilateral separation of duties, cryptographic provenance, and immutable audit logs.

Every fact reported in a CRICE intelligence dossier is backed by:
1. An atomic, cited primary evidence record snapshot.
2. An inherited deterministic source reliability rating ($A$ through $F$).
3. A multi-attribute entity resolution confidence tier ($1$ through $3$).
4. Mandatory independent multi-source corroboration for all adverse findings.

---

## 2. Core Architectural Principles

1. **Server-Side Enforcement Over UI Constraints**: No state transition, role check, or data validation relies on UI state or hidden form fields. All rules are strictly enforced within atomic service-layer transactions.
2. **Append-Only, Immutable Auditability**: Every operational state change, access attempt, approval, denial, rework loop, and recall is written to an immutable `audit_log` table protected by a database-level trigger blocking `UPDATE` and `DELETE`.
3. **Bilateral Separation of Duties**: An operator who works or creates a case can never act as its reviewer (`operator_id != reviewer_id`). This constraint is enforced at both the application service layer and via a PostgreSQL `CHECK` constraint.
4. **Strict B2B Governance & Purpose Limitation**: No investigation may be initiated without a verified, contracted client (`msa_signed = True`, `client_kyc_verified = True`) and a legally permissible, closed-enumeration purpose.
5. **Deterministic Evidentiary Provenance**: Findings are never generated from free-form hallucinations. Every finding comprises one or more atomic claims that cite primary accepted records. Source reliability ratings ($A$ to $F$) are deterministic and non-negotiable.
6. **Robust Adverse Finding Verification (Section 7 Gate)**: Uncorroborated single-source adverse allegations cannot be published as confirmed findings. Adverse claims require either government registry verification or corroboration across multiple distinct originating domains.
7. **Controlled Rework Loops & Post-Release Recall**: Intelligence workflows require revisions when evidentiary gaps appear. Reviewers and Compliance Admins can return cases for targeted rework with mandatory justification, or recall closed dossiers, incrementing versions and revoking active delivery links.

---

## 3. The 9-Stage DAG State Machine

CRICE models investigation lifecycles as a directed graph supporting forward stage progression, backward rework loops, and post-close recall.

```
       [INTAKE_DRAFT]
             │
             ▼
     [COMPLIANCE_GATE] ──(Auto-advance / Admin Approval)──┐
             │                                            │
             ▼                                            ▼
         [COLLECT] ◄──────────────────────────────┐   [COLLECT]
             │                                    │       │
             ▼                                    │       │
    [CLAIM_EXTRACTION]                            │       │
             │                                    │       │
             ▼                                    │       │
 [CORRELATION_AND_SCORING] ◄──────────────────┐   │       │
             │                                │   │       │
             ▼                                │   │       │
    [INDEPENDENT_REVIEW] ──(Reviewer Rework)──┴───┘       │
             │                                            │
             ▼ (Review Passed)                            │
       [BUILD_AND_QA]                                     │
             │                                            │
             ▼                                            │
       [RELEASE_GATE] ──(Compliance Admin Rework)─────────┤
             │                                            │
             ▼ (Release Approved)                         │
          [CLOSED]                                        │
             │                                            │
             ▼ (Recall Triggered)                         │
         [RECALLED] ──(Admin Reopen for Rework)───────────┘
```

### Stage Definitions & Guard Conditions

#### 1. `INTAKE_DRAFT` (Actor: `operator`)
* **Purpose**: Intake case drafting, client assignment, and scope definition.
* **Requirements**:
  * Verified active B2B Client: `client_name` provided, with `client_kyc_verified = True` and `msa_signed = True`.
  * Closed Purpose Enum: `corporate_due_diligence`, `litigation_support`, `vendor_verification`, `employee_screening_with_consent`, or `fraud_investigation`.
  * Subject Definition: `subject_type` (`company` or `person`), `subject_name`, and optional disambiguation identifiers (CIN, DIN, registration number).
* **Transitions Out**:
  * -> `COLLECT` (Auto-advance): Allowed when `subject_type == 'company'` AND `purpose` in (`corporate_due_diligence`, `litigation_support`, `vendor_verification`) AND `client_kyc_verified == True` AND `msa_signed == True`.
  * -> `COMPLIANCE_GATE`: Triggered if `subject_type == 'person'`, or `purpose == 'fraud_investigation'`, or `purpose == 'employee_screening_with_consent'`.

#### 2. `COMPLIANCE_GATE` (Actor: `compliance_admin` / `System`)
* **Purpose**: Human compliance review for sensitive subjects, high-risk investigations, or consent-gated employee screenings.
* **Guard Rules**:
  * **Human Gate Rule**: Person subjects and fraud investigations require explicit approval by `compliance_admin`.
  * **Consent Gate Rule**: If `purpose == 'employee_screening_with_consent'`, the system blocks approval until `consent_verified == True` (cryptographic consent token verified).
* **Transitions Out**:
  * -> `COLLECT`: Compliance administrator approves intake (writes `intake_approved` audit log).
  * -> `INTAKE_DRAFT`: Returned for corrections with mandatory reason.

#### 3. `COLLECT` (Actor: `operator`)
* **Purpose**: Targeted multi-source evidence acquisition according to the Source Charter.
* **Operational Actions**:
  * Execution of charter modules across designated open source, corporate registry, and public record domains.
  * Triage of raw evidence snapshots as `ACCEPTED` or `REJECTED`.
* **Exit Gate**: Cannot advance until all mandatory charter sources report `FOUND`, `NOT_FOUND`, or `FAILED` (degraded mode), and at least one record is `ACCEPTED` (or explicit operator sign-off on zero findings).
* **Transitions Out**:
  * -> `CLAIM_EXTRACTION`: Operator submits accepted collection for claim extraction.

#### 4. `CLAIM_EXTRACTION` (Actor: `System` / `operator`)
* **Purpose**: Decomposition of accepted evidence into atomic, factual claims.
* **Rules**:
  * Automated extraction or manual authoring strictly on `ACCEPTED` records.
  * Every claim must cite at least one `record_id` belonging to the case.
  * Source Reliability Rating ($A$–$F$) is deterministically inherited from the cited record's Source Charter tier. Operators may only downgrade reliability with an explicit reason string.
* **Transitions Out**:
  * -> `CORRELATION_AND_SCORING`: Operator advances extracted claims to entity resolution.

#### 5. `CORRELATION_AND_SCORING` (Actor: `operator` + Correlation Engine)
* **Purpose**: Entity resolution, identity confidence scoring, finding clustering, and adverse flag assignment.
* **Rules**:
  * Entity Resolution Match Tiers:
    * `TIER_1`: Exact deterministic identifier match (CIN, DIN, Tax ID, National ID).
    * `TIER_2`: Strong multi-attribute convergence (Full legal name + DOB/incorporation date + registered address).
    * `TIER_3`: Contextual probabilistic match (Name similarity + industry/geo overlap; requires corroboration).
  * Identity-Match Confidence Score ($1$ to $6$).
  * Adverse Flagging: Mark claims as `is_adverse = True/False`.
  * Finding Groups: Corroborating claims are clustered into `finding_group_id` containers.
* **Transitions Out**:
  * -> `INDEPENDENT_REVIEW`: Advances to review once all claims have match tiers and finding group assignments.

#### 6. `INDEPENDENT_REVIEW` (Actor: `reviewer`)
* **Purpose**: Rigorous peer review by an independent intelligence reviewer.
* **Requirements & Separation of Duties**:
  * `cases.reviewer_id` must be assigned by `compliance_admin` prior to entering this stage.
  * Strict constraint: `reviewer_id != operator_id`.
* **Actions**:
  * Reviewer inspects each claim and finding group against raw evidence snapshots (`Approve`, `Edit`, `Reject`).
* **Rework Loops**:
  * Reviewer may reject the case back to `COLLECT` or `CORRELATION_AND_SCORING`. Mandatory `rework_reason` (min 10 characters) is required and audited.
* **Section 7 Adverse-Claim Gate**:
  * Upon review completion, all approved claims with `is_adverse == True` must satisfy:
    1. Identity match is `TIER_1`, OR `TIER_2` across $\ge 2$ distinct attributes; AND
    2. Finding group contains $\ge 2$ independent originating sources (distinct `origin_source_domain` / syndication group), OR $\ge 1$ government registry source (`is_government_record == True`) with a `TIER_1` match.
  * Adverse claims failing this test are automatically downgraded to `UNRESOLVED_POSSIBLE_MATCH` and excluded from confirmed findings.
* **Transitions Out**:
  * -> `BUILD_AND_QA`: Reviewer approves case.
  * -> `CORRELATION_AND_SCORING` / `COLLECT`: Returned for rework.

#### 7. `BUILD_AND_QA` (Actor: `operator` / `System`)
* **Purpose**: Compilation of versioned intelligence dossier and coverage manifest.
* **Deliverables**:
  * Versioned dossier (`v1.0`, `v2.0` upon recall).
  * Disambiguation block (confirmed identifiers, cleared aliases, false-positive exclusions).
  * Coverage manifest (catalog of all queried charter sources, status, timestamps).
  * Cryptographic SHA-256 integrity hash computed over compiled dossier data.
* **Transitions Out**:
  * -> `RELEASE_GATE`: Operator submits compiled dossier for release sign-off.

#### 8. `RELEASE_GATE` (Actor: `compliance_admin`)
* **Purpose**: Final executive and legal sign-off.
* **Actions**:
  * Compliance admin inspects compiled dossier, coverage manifest, and audit history.
* **Transitions Out**:
  * -> `CLOSED`: Approve and issue secure delivery link.
  * -> `BUILD_AND_QA` or `INDEPENDENT_REVIEW`: Return for rework with mandatory justification.

#### 9. `CLOSED` & `RECALLED` (Actor: `compliance_admin`)
* **Purpose**: Terminal delivery state and audited recall mechanism.
* **Recall Mechanism (`CLOSED` -> `RECALLED` -> `COLLECT` or `INDEPENDENT_REVIEW`)**:
  * Only `compliance_admin` can trigger a recall on a `CLOSED` case.
  * Mandatory recall reason ($\ge 10$ characters) logged in `audit_log`.
  * `cases.is_recalled` is set to `True`.
  * `cases.dossier_version` increments (`v1.0` -> `v2.0`).
  * Any active secure delivery links are immediately revoked.
  * Case reopens in `COLLECT` (if new collection needed) or `INDEPENDENT_REVIEW` (if re-evaluating existing findings).

---

## 4. Transition Matrix & Role Permissions

| Current Stage | Target Stage | Allowed Actor Roles | Mandatory Conditions & Guards |
|---|---|---|---|
| `INTAKE_DRAFT` | `COLLECT` | `System` / `operator` | Auto-advance: Company subject + standard corporate purpose + client KYC & MSA verified. |
| `INTAKE_DRAFT` | `COMPLIANCE_GATE` | `operator` | Person subject OR fraud investigation OR consent purpose. |
| `COMPLIANCE_GATE` | `COLLECT` | `compliance_admin` | Human approval. If `employee_screening_with_consent`, requires `consent_verified == True`. |
| `COMPLIANCE_GATE` | `INTAKE_DRAFT` | `compliance_admin` | Rework: Requires `rework_reason` ($\ge 10$ chars). |
| `COLLECT` | `CLAIM_EXTRACTION` | `operator`, `compliance_admin` | M1 pass-through / M2 exit gate: all charter sources resolved. |
| `CLAIM_EXTRACTION` | `CORRELATION_AND_SCORING` | `operator`, `compliance_admin` | M1 pass-through / M2 exit gate: all accepted records extracted. |
| `CORRELATION_AND_SCORING` | `INDEPENDENT_REVIEW` | `operator`, `compliance_admin` | Requires assigned `reviewer_id IS NOT NULL` and `reviewer_id != operator_id`. |
| `INDEPENDENT_REVIEW` | `BUILD_AND_QA` | `reviewer` | Assigned reviewer only (`reviewer_id == user.id`). Section 7 adverse claim gate passes. |
| `INDEPENDENT_REVIEW` | `CORRELATION_AND_SCORING` | `reviewer` | Rework: Requires `rework_reason` ($\ge 10$ chars). |
| `INDEPENDENT_REVIEW` | `COLLECT` | `reviewer` | Rework: Requires `rework_reason` ($\ge 10$ chars). |
| `BUILD_AND_QA` | `RELEASE_GATE` | `operator`, `compliance_admin` | Dossier compiled, SHA-256 generated. |
| `BUILD_AND_QA` | `INDEPENDENT_REVIEW` | `operator`, `compliance_admin` | Rework: Requires `rework_reason` ($\ge 10$ chars). |
| `RELEASE_GATE` | `CLOSED` | `compliance_admin` | Final release sign-off. |
| `RELEASE_GATE` | `BUILD_AND_QA` | `compliance_admin` | Rework: Requires `rework_reason` ($\ge 10$ chars). |
| `RELEASE_GATE` | `INDEPENDENT_REVIEW` | `compliance_admin` | Rework: Requires `rework_reason` ($\ge 10$ chars). |
| `CLOSED` | `RECALLED` | `compliance_admin` | Recall: Requires `rework_reason` ($\ge 10$ chars). Sets `is_recalled = True`, increments `dossier_version`. |
| `RECALLED` | `COLLECT` | `compliance_admin` | Reopen recalled case for new collection. |
| `RECALLED` | `INDEPENDENT_REVIEW` | `compliance_admin` | Reopen recalled case for re-review. |

---

## 5. Security & Provenance Specifications

### Authentication & Session Security
* Passwords hashed using Argon2id (`argon2-cffi`).
* TOTP Multi-Factor Authentication via `pyotp`.
* TOTP secrets encrypted at rest via AES-128-CBC / HMAC-SHA256 (Fernet).
* TOTP Replay Protection: `totp_used` table prevents token reuse within valid windows.
* Server-Side DB Sessions: Session cookies store only an opaque `session_id`. Database records hold `user_id`, `mfa_verified`, `csrf_token`, `last_active_at`, `created_at`, `revoked`.
* Idle Timeout: 8 hours. Absolute Timeout: 24 hours.
* Account Lockout: 5 consecutive failed attempts trigger 15-minute lockout.

### Audit Log Integrity
* Append-only table: `audit_log`.
* Fields: `id`, `timestamp` (UTC), `user_id`, `case_id`, `action`, `from_stage`, `to_stage`, `allowed`, `detail`, `ip`.
* PostgreSQL trigger: `trg_audit_log_immutable` raises an exception on any `UPDATE` or `DELETE` attempt.
* Total Audit Coverage: Failed/denied attempts (`allowed = False`) are committed even when an HTTP 400/403 exception is raised.

---

## 6. Milestone Staging Strategy

* **Milestone 1 (Current)**: Core Skeleton & DAG State Machine. Implements the full 10-state schema, stage transition engine, rework and recall loops, KYC/MSA and consent gates, bilateral separation of duties, and security infrastructure. Stages 3–7 operate with verified pass-through triggers.
* **Milestone 2**: Source Charter & Automated Collection Engine (Records schema, snapshot storage).
* **Milestone 3**: Atomic Claim Extraction & Deterministic Source Reliability ($A$–$F$).
* **Milestone 4**: Entity Resolution Engine & Section 7 Adverse Corroboration Gates.
* **Milestone 5**: Automated Dossier Compilation, QA Manifests & PDF Generation.
* **Milestone 6**: Cryptographic Delivery & Public Verification Portals.
