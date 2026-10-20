"""
app/claims/scoring.py – Indian-Context Entity Resolution & Two-Axis Scoring Engine.

Implements Fellegi-Sunter deterministic entity resolution adapted for Indian corporate
and personal identities (CIN, DIN, PAN, GSTIN, transliterations, and multi-attribute links).
Computes two-axis scores: Source Reliability (A–F) x Identity Confidence (1–6).
"""
import json
import re
from typing import Any, Optional, Tuple

from app.models import Case, Claim, MatchTier


# ── 1. Indian Name & Corporate Suffix Normalization ──────────────────────────

HONORIFICS = [
    r"\bshri\b", r"\bsmt\b", r"\bkumari\b", r"\bmr\b", r"\bmrs\b", r"\bms\b",
    r"\bdr\b", r"\badv\b", r"\bprof\b", r"\blate\b", r"\bm/s\b", r"\bm/s\.\b",
]

CORP_SUFFIXES = [
    r"\bprivate limited\b", r"\bpvt\.?\s*ltd\.?\b", r"\blimited\b", r"\bltd\.?\b",
    r"\bllp\b", r"\bl\.l\.p\.?\b",
]

TRANSLITERATION_MAP = {
    r"\b(?:mohammad|muhammad|mohammed|mohd)\b": "mohd",
    r"\b(?:agarwal|aggarwal|agrawal)\b": "agarwal",
    r"\b(?:chatterjee|chattopadhyay)\b": "chatterjee",
    r"\b(?:banerjee|bandyopadhyay)\b": "banerjee",
    r"\b(?:mukherjee|mukhopadhyay)\b": "mukherjee",
    r"\b(?:sengupta|sen\s+gupta)\b": "sengupta",
    r"\b(?:kumar|kr\.?)\b": "kumar",
}


def normalize_identifier(val: Optional[str]) -> str:
    """Normalize alphanumeric hard identifiers (CIN, DIN, GSTIN, PAN)."""
    if not val:
        return ""
    return re.sub(r"[^A-Za-z0-9]", "", val).upper()


def normalize_indian_name(name: Optional[str]) -> str:
    """Normalize Indian personal or company name for deterministic comparison."""
    if not name:
        return ""
    n = name.lower().strip()

    # Strip honorifics
    for pat in HONORIFICS:
        n = re.sub(pat, "", n, flags=re.IGNORECASE)

    # Strip corporate suffixes
    for pat in CORP_SUFFIXES:
        n = re.sub(pat, "", n, flags=re.IGNORECASE)

    # Normalize transliteration variants
    for pat, rep in TRANSLITERATION_MAP.items():
        n = re.sub(pat, rep, n, flags=re.IGNORECASE)

    # Remove non-alphanumeric (keep single space)
    n = re.sub(r"[^a-z0-9\s]", " ", n)
    n = re.sub(r"\s+", " ", n).strip()
    return n


def _normalize_ws(s: Optional[str]) -> str:
    """Collapse whitespace and strip string."""
    if not s:
        return ""
    return re.sub(r"\s+", " ", s).strip()


def _is_initial_token_match(norm_a: str, norm_b: str) -> bool:
    """Check if tokens match with initials, e.g. 'R K Sharma' matches 'Rajesh Kumar Sharma'."""
    tokens_a = norm_a.split()
    tokens_b = norm_b.split()
    if not tokens_a or not tokens_b:
        return False
    if len(tokens_a) != len(tokens_b):
        return False
    # Check if corresponding tokens match in full or as initials
    all_matched = True
    for ta, tb in zip(tokens_a, tokens_b):
        if ta == tb:
            continue
        if (len(ta) == 1 and tb.startswith(ta)) or (len(tb) == 1 and ta.startswith(tb)):
            continue
        all_matched = False
        break
    return all_matched


# ── 2. Two-Axis Scoring & Entity Resolution ──────────────────────────────────


def score_claim_entity_match(case: Case, claim: Claim) -> Tuple[str, int, list[str], str]:
    """
    Score entity match between Case anchor and Claim extracted identifiers.
    Returns (match_tier, identity_confidence, matched_attributes, scoring_rationale).
    """
    matched_attrs: list[str] = []
    case_cin = normalize_identifier(case.subject_identifier)
    case_din = normalize_identifier(case.subject_din)
    case_pan_gstin = normalize_identifier(case.subject_pan_or_gstin)

    # Parse claim extracted identifiers
    try:
        extracted = json.loads(claim.extracted_identifiers_json or "{}")
    except Exception:
        extracted = {}

    claim_cin = normalize_identifier(extracted.get("cin"))
    claim_din = normalize_identifier(extracted.get("din"))
    claim_gstin = normalize_identifier(extracted.get("gstin"))
    claim_pan = normalize_identifier(extracted.get("pan"))
    claim_domain = (extracted.get("domain") or "").lower()

    # Search raw quote / content for hard identifiers if not in extracted dict
    content_search = f"{claim.verbatim_quote or ''} {claim.object_value} {claim.primary_record.raw_content if claim.primary_record else ''}"
    norm_content_search = normalize_identifier(content_search)

    # Check for hard identifier conflicts first (e.g. different DIN for same person name)
    if case_din and claim_din and case_din != claim_din:
        return (
            MatchTier.TIER_3.value,
            6,
            ["HARD_IDENTIFIER_CONFLICT"],
            f"Conflicting DIN: case requires {case.subject_din} but claim cites {extracted.get('din')}.",
        )

    # ── Tier 1 Matches (Exact Hard Identifier) ────────────────────────────────
    if case_cin and (claim_cin == case_cin or case_cin in norm_content_search):
        matched_attrs.append("CIN_EXACT")
    if case_din and (claim_din == case_din or case_din in norm_content_search):
        matched_attrs.append("DIN_EXACT")
    if case_pan_gstin and (
        (claim_gstin and claim_gstin == case_pan_gstin)
        or (claim_pan and claim_pan == case_pan_gstin)
        or case_pan_gstin in norm_content_search
    ):
        matched_attrs.append("PAN_GSTIN_EXACT")

    if matched_attrs:
        return (
            MatchTier.TIER_1.value,
            1,
            matched_attrs,
            f"Tier 1 Deterministic Match via hard identifier(s): {', '.join(matched_attrs)}.",
        )

    # ── Name Matching ─────────────────────────────────────────────────────────
    norm_case_name = normalize_indian_name(case.subject_name)
    norm_claim_subj = normalize_indian_name(claim.subject_entity)
    norm_claim_extracted_name = normalize_indian_name(extracted.get("name"))

    name_matched = False
    name_attr = None
    if norm_case_name and norm_claim_subj and norm_case_name == norm_claim_subj:
        name_matched = True
        name_attr = "NAME_EXACT"
    elif norm_case_name and norm_claim_extracted_name and norm_case_name == norm_claim_extracted_name:
        name_matched = True
        name_attr = "NAME_EXACT"
    elif norm_case_name and (norm_case_name in norm_content_search.lower() or _normalize_ws(case.subject_name).lower() in content_search.lower()):
        name_matched = True
        name_attr = "NAME_FOUND_IN_RECORD"
    elif norm_case_name and norm_claim_subj and _is_initial_token_match(norm_case_name, norm_claim_subj):
        name_matched = True
        name_attr = "NAME_INITIAL_MATCH"

    if name_matched:
        matched_attrs.append(name_attr or "NAME_MATCH")

        # ── Check Tier 2 Attributes ───────────────────────────────────────────
        t2_count = 0
        # 1. Address / City
        if case.subject_address:
            norm_case_addr = normalize_indian_name(case.subject_address)
            if norm_case_addr and any(word in content_search.lower() for word in norm_case_addr.split() if len(word) > 4):
                matched_attrs.append("ADDRESS_MATCH")
                t2_count += 1

        # 2. DOB / Year of incorporation/birth
        if case.subject_dob_or_year:
            clean_year = re.sub(r"[^\d]", "", case.subject_dob_or_year)
            if clean_year and len(clean_year) >= 4 and clean_year[:4] in content_search:
                matched_attrs.append("DOB_OR_YEAR_MATCH")
                t2_count += 1

        # 3. Father / Spouse name
        if case.subject_father_or_spouse:
            norm_rel = normalize_indian_name(case.subject_father_or_spouse)
            if norm_rel and norm_rel in content_search.lower():
                matched_attrs.append("FATHER_OR_SPOUSE_MATCH")
                t2_count += 1

        # 4. Domain match (e.g. acmetech.demo matches case subject_identifier)
        if claim_domain and case.subject_identifier and claim_domain in case.subject_identifier.lower():
            matched_attrs.append("DOMAIN_ANCHOR_MATCH")
            t2_count += 1

        # ── Multi-Attribute Tier 2 (>= 2 secondary attributes) ────────────────
        if t2_count >= 2:
            return (
                MatchTier.TIER_2.value,
                2,
                matched_attrs,
                f"Tier 2 Strong Match: name matched with {t2_count} corroborating secondary attributes ({', '.join(matched_attrs)}).",
            )
        # ── Single Tier 2 Attribute ───────────────────────────────────────────
        elif t2_count == 1:
            return (
                MatchTier.TIER_2.value,
                3,
                matched_attrs,
                f"Tier 2 Single-Attribute Match: name matched with 1 secondary attribute ({', '.join(matched_attrs)}).",
            )
        # ── Tier 3 (Name + City or Name Only) ─────────────────────────────────
        else:
            if case.subject_city and case.subject_city.lower() in content_search.lower():
                matched_attrs.append("CITY_MATCH")
                return (
                    MatchTier.TIER_3.value,
                    4,
                    matched_attrs,
                    "Tier 3 Contextual Match: name and city matched without secondary corroborating attributes.",
                )
            else:
                return (
                    MatchTier.TIER_3.value,
                    5,
                    matched_attrs,
                    "Tier 3 Weak Match: name similarity only. High common-name collision risk.",
                )

    # ── No Name or Identifier Match ───────────────────────────────────────────
    return (
        MatchTier.TIER_3.value,
        6,
        ["NO_IDENTIFIER_MATCH"],
        "Unverified / Pending Match: no hard identifiers or legal names matched case anchor.",
    )
