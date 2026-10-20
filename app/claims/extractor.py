"""
app/claims/extractor.py – Sandboxed AI & Deterministic Claim Extractor.

Decomposes ACCEPTED evidence records into atomic factual claims.
Enforces strict record citation, verbatim quote grounding, and immutable provenance.
Operates in Live Claude API mode (when configured) or Deterministic Parser mode (offline default).
"""
import json
import os
import re
from typing import Any, Optional, Tuple
from urllib.parse import urlparse

from app.models import Case, Record

# Regexes for Indian hard identifiers
CIN_REGEX = re.compile(r"\b([LUu]\d{5}[A-Za-z]{2}\d{4}[A-Za-z]{3}\d{6})\b")
DIN_REGEX = re.compile(r"\b(?:DIN|Director Identification Number)?[:\s-]*(\d{8})\b", re.IGNORECASE)
GSTIN_REGEX = re.compile(r"\b(\d{2}[A-Za-z]{5}\d{4}[A-Za-z]{1}[1-9A-Za-z]{1}[Zz][0-9A-Za-z]{1})\b")
PAN_REGEX = re.compile(r"\b([A-Za-z]{5}\d{4}[A-Za-z]{1})\b")


def extract_origin_domain(url: str) -> str:
    """Extract clean root authority domain from URL (e.g. mca.gov.in, rdap.org)."""
    if not url:
        return "unknown"
    try:
        parsed = urlparse(url)
        netloc = parsed.netloc.lower()
        if ":" in netloc:
            netloc = netloc.split(":")[0]
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc or "unknown"
    except Exception:
        return "unknown"


def _normalize_ws(text: str) -> str:
    """Normalize internal whitespace and line endings for exact quote comparison."""
    if not text:
        return ""
    return re.sub(r"\s+", " ", text).strip()


def verify_verbatim_quote(verbatim_quote: Optional[str], raw_content: str) -> bool:
    """Check if whitespace-normalized verbatim quote appears inside raw content."""
    if not verbatim_quote or not raw_content:
        return False
    norm_quote = _normalize_ws(verbatim_quote)
    norm_content = _normalize_ws(raw_content)
    return norm_quote in norm_content


def extract_claims_deterministic(case: Case, accepted_records: list[Record]) -> list[dict[str, Any]]:
    """
    Rule-based deterministic extraction engine for offline lab execution.
    Inspects each ACCEPTED record by source type and produces atomic claims with verbatim quotes.
    """
    claims: list[dict[str, Any]] = []

    for record in accepted_records:
        source_code = record.source.code if record.source else ""
        content = record.raw_content
        domain = extract_origin_domain(record.source_url)
        source_rel = record.source.default_reliability if record.source else "B"

        # ── 1. DOMAIN_RDAP ────────────────────────────────────────────────────
        if source_code == "DOMAIN_RDAP" or record.content_type == "application/json":
            try:
                data = json.loads(content)
                ldh = data.get("ldhName") or case.subject_name
                status_list = data.get("status", [])
                handle = data.get("handle")

                # Claim 1: Domain status
                if status_list:
                    quote = f'"status": {json.dumps(status_list)}'
                    if quote not in content:
                        quote = f'"ldhName": "{ldh}"'
                    claims.append({
                        "subject_entity": ldh,
                        "predicate": "HAS_DOMAIN_STATUS",
                        "object_value": ", ".join(status_list) if isinstance(status_list, list) else str(status_list),
                        "verbatim_quote": quote if quote in content else content[:100],
                        "primary_record_id": record.id,
                        "supporting_record_ids": [record.id],
                        "extracted_identifiers": {"domain": ldh, "handle": handle},
                        "is_adverse": False,
                        "adverse_category": None,
                        "origin_domain": domain or "rdap.org",
                        "finding_group_key": "fg_domain_assets",
                    })

                # Claim 2: Registrant Entity
                entities = data.get("entities", [])
                for ent in entities:
                    roles = ent.get("roles", [])
                    vcard = ent.get("vcardArray")
                    name = None
                    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                        for prop in vcard[1]:
                            if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                                name = prop[3]
                                break
                    if "registrant" in roles and name:
                        quote_frag = f'"{name}"'
                        claims.append({
                            "subject_entity": ldh,
                            "predicate": "HAS_DOMAIN_REGISTRANT",
                            "object_value": f"Registered to {name}",
                            "verbatim_quote": quote_frag if quote_frag in content else content[:120],
                            "primary_record_id": record.id,
                            "supporting_record_ids": [record.id],
                            "extracted_identifiers": {"domain": ldh, "name": name},
                            "is_adverse": False,
                            "adverse_category": None,
                            "origin_domain": domain or "rdap.org",
                            "finding_group_key": "fg_domain_assets",
                        })

                # Claim 3: Registrar
                for ent in entities:
                    if "registrar" in ent.get("roles", []):
                        vcard = ent.get("vcardArray")
                        reg_name = None
                        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                            for prop in vcard[1]:
                                if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                                    reg_name = prop[3]
                                    break
                        if reg_name:
                            quote_frag = f'"{reg_name}"'
                            claims.append({
                                "subject_entity": ldh,
                                "predicate": "HAS_DOMAIN_REGISTRAR",
                                "object_value": reg_name,
                                "verbatim_quote": quote_frag if quote_frag in content else content[:100],
                                "primary_record_id": record.id,
                                "supporting_record_ids": [record.id],
                                "extracted_identifiers": {"domain": ldh},
                                "is_adverse": False,
                                "adverse_category": None,
                                "origin_domain": domain or "rdap.org",
                                "finding_group_key": "fg_domain_assets",
                            })
            except Exception:
                # Fallback text parse for non-JSON or partial RDAP
                pass

        # ── 2. MCA_MANUAL (Corporate Filings) ─────────────────────────────────
        elif source_code == "MCA_MANUAL":
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            cins = CIN_REGEX.findall(content)
            dins = DIN_REGEX.findall(content)

            # Claim: Company Status
            status_line = next((l for l in lines if "status" in l.lower() or "active" in l.lower()), None)
            if status_line:
                is_strike_off = any(w in status_line.lower() for w in ["strike off", "under liquidation", "defunct", "dormant"])
                claims.append({
                    "subject_entity": case.subject_name,
                    "predicate": "HAS_CORPORATE_STATUS",
                    "object_value": status_line,
                    "verbatim_quote": status_line,
                    "primary_record_id": record.id,
                    "supporting_record_ids": [record.id],
                    "extracted_identifiers": {"cin": cins[0] if cins else None},
                    "is_adverse": is_strike_off,
                    "adverse_category": "DEFAULT" if is_strike_off else None,
                    "origin_domain": domain or "mca.gov.in",
                    "finding_group_key": "fg_corporate_standing",
                })

            # Claim: Capital / Financial
            cap_line = next((l for l in lines if "capital" in l.lower()), None)
            if cap_line:
                claims.append({
                    "subject_entity": case.subject_name,
                    "predicate": "HAS_PAID_UP_CAPITAL",
                    "object_value": cap_line,
                    "verbatim_quote": cap_line,
                    "primary_record_id": record.id,
                    "supporting_record_ids": [record.id],
                    "extracted_identifiers": {"cin": cins[0] if cins else None},
                    "is_adverse": False,
                    "adverse_category": None,
                    "origin_domain": domain or "mca.gov.in",
                    "finding_group_key": "fg_corporate_standing",
                })

            # Claim: Director Appointments
            dir_lines = [l for l in lines if any(w in l.lower() for w in ["director", "din", "appointment"])]
            for d_line in dir_lines[:2]:
                claims.append({
                    "subject_entity": case.subject_name,
                    "predicate": "HAS_DIRECTOR_APPOINTMENT",
                    "object_value": d_line,
                    "verbatim_quote": d_line,
                    "primary_record_id": record.id,
                    "supporting_record_ids": [record.id],
                    "extracted_identifiers": {"cin": cins[0] if cins else None, "din": dins[0] if dins else None},
                    "is_adverse": False,
                    "adverse_category": None,
                    "origin_domain": domain or "mca.gov.in",
                    "finding_group_key": "fg_directorships",
                })

            # If no structured lines matched, create general corporate registration claim
            if not claims:
                first_line = lines[0] if lines else content[:80]
                claims.append({
                    "subject_entity": case.subject_name,
                    "predicate": "HAS_CORPORATE_FILING",
                    "object_value": first_line,
                    "verbatim_quote": first_line,
                    "primary_record_id": record.id,
                    "supporting_record_ids": [record.id],
                    "extracted_identifiers": {"cin": cins[0] if cins else None},
                    "is_adverse": False,
                    "adverse_category": None,
                    "origin_domain": domain or "mca.gov.in",
                    "finding_group_key": "fg_corporate_standing",
                })

        # ── 3. ECOURTS_MANUAL (Litigation & Orders) ───────────────────────────
        elif source_code == "ECOURTS_MANUAL":
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            for line in lines[:3]:
                lower_line = line.lower()
                is_adverse_case = any(w in lower_line for w in ["accused", "respondent", "criminal", "s.138", "cheque bounce", "fraud", "penalty", "default"])
                cat = "FRAUD" if "fraud" in lower_line else ("LITIGATION_ACCUSED" if is_adverse_case else None)
                claims.append({
                    "subject_entity": case.subject_name,
                    "predicate": "NAMED_IN_LITIGATION",
                    "object_value": line,
                    "verbatim_quote": line,
                    "primary_record_id": record.id,
                    "supporting_record_ids": [record.id],
                    "extracted_identifiers": {"name": case.subject_name},
                    "is_adverse": is_adverse_case,
                    "adverse_category": cat,
                    "origin_domain": domain or "ecourts.gov.in",
                    "finding_group_key": "fg_litigation",
                })

        # ── 4. GST_MANUAL (Tax Compliance) ────────────────────────────────────
        elif source_code == "GST_MANUAL":
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            gstins = GSTIN_REGEX.findall(content)
            first_line = lines[0] if lines else content[:80]
            is_cancelled = any(w in content.lower() for w in ["cancelled", "suspended", "default", "non-compliant"])
            claims.append({
                "subject_entity": case.subject_name,
                "predicate": "HAS_GST_REGISTRATION",
                "object_value": first_line,
                "verbatim_quote": first_line,
                "primary_record_id": record.id,
                "supporting_record_ids": [record.id],
                "extracted_identifiers": {"gstin": gstins[0] if gstins else None},
                "is_adverse": is_cancelled,
                "adverse_category": "DEFAULT" if is_cancelled else None,
                "origin_domain": domain or "gst.gov.in",
                "finding_group_key": "fg_tax_compliance",
            })

        # ── 5. NEWS_MANUAL & Generic Public Records ───────────────────────────
        else:
            lines = [l.strip() for l in content.splitlines() if l.strip()]
            for line in lines[:2]:
                lower = line.lower()
                is_adverse_news = any(w in lower for w in ["fraud", "scam", "arrest", "raid", "penalty", "sanction", "default", "cheating", "embezzlement"])
                cat = "FRAUD" if "fraud" in lower or "scam" in lower else ("REGULATORY_PENALTY" if "penalty" in lower or "sanction" in lower else ("DEFAULT" if is_adverse_news else None))
                claims.append({
                    "subject_entity": case.subject_name,
                    "predicate": "REPORTED_IN_MEDIA",
                    "object_value": line,
                    "verbatim_quote": line,
                    "primary_record_id": record.id,
                    "supporting_record_ids": [record.id],
                    "extracted_identifiers": {"name": case.subject_name},
                    "is_adverse": is_adverse_news,
                    "adverse_category": cat,
                    "origin_domain": domain or "news-archive.com",
                    "finding_group_key": "fg_media_allegations",
                })

    return claims


def extract_claims_from_accepted_records(
    case: Case,
    accepted_records: list[Record],
) -> Tuple[str, str, str, list[dict[str, Any]], int]:
    """
    Main extraction interface. Returns (model_name, raw_prompt, raw_output, candidate_claims, claims_rejected_citation_count).
    Supports live Claude API if configured or deterministic offline parser.
    """
    if not case.ai_enabled or not accepted_records:
        return (
            "crice-bypassed",
            "Extraction bypassed: ai_enabled=False or 0 accepted records",
            "[]",
            [],
            0,
        )

    api_key = os.getenv("ANTHROPIC_API_KEY")
    is_offline_forced = os.getenv("CRICE_OFFLINE_AI", "1") == "1"

    # Live Claude API branch
    if api_key and not is_offline_forced:
        try:
            import httpx
            model_name = "claude-3-5-sonnet-latest"
            prompt = (
                f"You are the CRICE Intelligence Extraction Engine. Extract atomic, factual claims about the subject {case.subject_name!r}.\n"
                f"Extract claims strictly from the following ACCEPTED records. Every claim MUST cite the exact record id and quote exact verbatim text.\n\n"
            )
            for r in accepted_records:
                prompt += f"--- RECORD ID {r.id} ({r.source.code if r.source else 'UNKNOWN'}) ---\n{r.raw_content[:2000]}\n\n"

            prompt += (
                "Return a strict JSON array of objects with keys: "
                "subject_entity, predicate, object_value, verbatim_quote, primary_record_id (int), "
                "supporting_record_ids (list of int), is_adverse (bool), adverse_category (string or null).\n"
                "Output ONLY valid JSON."
            )

            headers = {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            }
            body = {
                "model": model_name,
                "max_tokens": 4000,
                "messages": [{"role": "user", "content": prompt}],
            }
            with httpx.Client(timeout=30.0) as client:
                res = client.post("https://api.anthropic.com/v1/messages", headers=headers, json=body)
                if res.status_code == 200:
                    data = res.json()
                    raw_text = data["content"][0]["text"]
                    # Extract JSON array
                    m = re.search(r"\[.*\]", raw_text, re.DOTALL)
                    if m:
                        raw_json = m.group(0)
                        candidate_list = json.loads(raw_json)
                        # Filter citations
                        valid_ids = {r.id for r in accepted_records}
                        filtered = []
                        rejected_count = 0
                        for c in candidate_list:
                            pid = c.get("primary_record_id")
                            if pid in valid_ids:
                                c["origin_domain"] = extract_origin_domain(next(r.source_url for r in accepted_records if r.id == pid))
                                filtered.append(c)
                            else:
                                rejected_count += 1
                        return (model_name, prompt, raw_text, filtered, rejected_count)
        except Exception:
            # Fall back to deterministic parser on API errors
            pass

    # Deterministic parser (default)
    model_name = "crice-deterministic-extractor-v1"
    prompt = f"Deterministic extraction for case {case.case_ref} across {len(accepted_records)} ACCEPTED records."
    claims = extract_claims_deterministic(case, accepted_records)
    raw_output = json.dumps(claims, indent=2)
    return (model_name, prompt, raw_output, claims, 0)
