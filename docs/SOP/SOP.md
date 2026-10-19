# CRICE Lab: Operator Standard Operating Procedures (SOP)

This document provides clear operational guidelines for handling cases across the CRICE 9-Stage DAG lifecycle.

---

## Roles & Responsibilities

| Role | Key Permissions | Responsibilities |
|---|---|---|
| **Operator** | Case creation, collection, extraction, correlation, building | Enters verified client/subject details; conducts reconnaissance; builds dossier. |
| **Reviewer** | Independent review, rework return | Inspects claims and evidence; cannot be the operator for the same case. |
| **Compliance Admin** | Intake approval, reviewer assignment, release, recall, user administration | Approves person-subject intake and consent; issues release sign-off; triggers recalls. |

---

## 1. Stage 1: INTAKE_DRAFT

1. Navigate to `/cases` and click **+ Open new case**.
2. Enter the **Client name** and verify that client KYC and MSA are verified.
3. Select the permissible investigation **Purpose**:
   - `corporate_due_diligence`
   - `litigation_support`
   - `vendor_verification`
   - `employee_screening_with_consent`
   - `fraud_investigation`
4. Select **Subject type**:
   - `Company`: Enter legal name and Company MCA CIN (if registered).
   - `Person`: Enter full legal name and Director Identification Number (DIN) or government ID if known.
5. Submit the intake form:
   - If the subject is a **Company** under standard commercial purposes with verified KYC/MSA, the case will **auto-advance directly to COLLECT**.
   - If the subject is a **Person**, or the purpose is **Fraud Investigation** or **Employee Screening**, the case will move to **COMPLIANCE_GATE**.

---

## 2. Stage 2: COMPLIANCE_GATE

*Awaiting Compliance Administrator Review.*
- **Operator Action**: Notify the Compliance Administrator. You cannot advance the case while it is in `COMPLIANCE_GATE`.
- **Compliance Admin Action**:
  - Review subject, client relationship, and legal basis.
  - If the purpose is `employee_screening_with_consent`, ensure that consent documentation is verified (`consent_verified = True`) before approving.
  - Click **Approve Intake** to move the case to `COLLECT`, or return to `INTAKE_DRAFT` if details are deficient.

---

## 3. Stage 3: COLLECT

- **Objective**: Execute reconnaissance across chartered sources (automated RDAP, manual registry captures), record coverage manifest status, and triage evidence into the immutable evidence vault.
- **Operator Actions**:
  1. **Automated Domain RDAP Execution**:
     - For subjects with corporate domain names, run the automated RDAP adapter.
     - The system queries authoritative RDAP services, stores canonicalized response payloads, and computes SHA-256 snapshot hashes automatically.
  2. **Tamper-Evident Manual Capture**:
     - For corporate registries (`MCA_MANUAL`, `GST_MANUAL`, `ECOURTS_MANUAL`, `NEWS_MANUAL`), query the designated registry.
     - Submit the manual capture record with source code, query input, outcome (`FOUND`, `NOT_FOUND`, `FAILED`), official source URL, and raw text snapshot ($\ge 20$ chars).
     - The system normalizes line endings and stamps the record with a cryptographically verifiable SHA-256 hash.
  3. **Inline Evidence Triage**:
     - Review each captured `Record` in the Evidence Vault.
     - Mark as **Accept** if the record matches the disambiguation criteria and contributes relevant factual evidence.
     - Mark as **Reject** if non-pertinent or spurious, providing a mandatory justification note ($\ge 5$ characters).
  4. **Stage Advancement Criteria**:
     - Ensure at least one chartered source run is completed (`FOUND`, `NOT_FOUND`, or `FAILED`).
     - Ensure **zero** records remain in `PENDING_TRIAGE`.
     - Advance to **Claim Extraction** if at least one record is `ACCEPTED`.
     - If all searches returned no matching records or all records were rejected, attest to **Zero Findings** via the checkbox before advancing.

---

## 4. Stage 4: CLAIM_EXTRACTION

- **Objective**: Synthesize atomic factual statements from verified findings.
- **Action**: In Milestone 1, click **Advance to Correlation & Scoring**.

---

## 5. Stage 5: CORRELATION_AND_SCORING

- **Objective**: Verify entity resolution match confidence and cluster corroborating claims.
- **Prerequisite**: A Reviewer must be assigned by Compliance Administrator before entering Independent Review.
- **Action**: Click **Advance to Independent Review**.

---

## 6. Stage 6: INDEPENDENT_REVIEW

*Locked for Reviewer Inspection.*
- **Operator Action**: Await reviewer feedback. You cannot approve or advance this stage.
- **Reviewer Action**:
  - Verify every claim against source evidence.
  - If evidentiary gaps or uncorroborated adverse claims exist, click **Return for Rework**, specify the mandatory rework reason ($\ge 10$ characters), and select `COLLECT` or `CORRELATION_AND_SCORING`.
  - If satisfied, click **Approve & Advance to Build & QA**.

---

## 7. Stage 7: BUILD_AND_QA

- **Objective**: Assemble versioned dossier, disambiguation block, and coverage manifest.
- **Action**: Operator clicks **Submit for Release Gate Sign-Off**.

---

## 8. Stage 8: RELEASE_GATE

*Executive Release Review.*
- **Compliance Admin Action**:
  - Inspect final dossier and audit history.
  - If changes are needed, click **Return for Rework** with a mandatory reason.
  - If approved, click **Release & Close Case**. The case transitions to `CLOSED`.

---

## 9. Stage 9: CLOSED & RECALLED

- **Status**: The case is officially delivered and closed.
- **Recall Procedure (Compliance Admin Only)**:
  - If new conflicting information arises post-release, Compliance Administrator clicks **Recall Dossier**.
  - A mandatory recall reason ($\ge 10$ characters) is entered.
  - Active delivery links are revoked, `dossier_version` increments from `v1.0` to `v2.0`, and the case re-opens in `COLLECT` or `INDEPENDENT_REVIEW` for correction.
