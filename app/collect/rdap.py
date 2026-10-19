"""
app/collect/rdap.py – Authoritative Domain RDAP Automated Adapter.

Queries RDAP (Registration Data Access Protocol) for domain registration,
status, dates, registrar, and registrant records.
Includes deterministic offline fallback for hermetic lab execution and tests.
"""
from dataclasses import dataclass
import hashlib
import json
import os
import re
from typing import Any, Optional

import httpx

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$"
)

# Deterministic simulated RDAP responses for hermetic environments / demo mode
_DEMO_RDAP_FIXTURES: dict[str, dict[str, Any]] = {
    "acmetech.demo": {
        "objectClassName": "domain",
        "handle": "DOM-ACME-DEMO-001",
        "ldhName": "acmetech.demo",
        "status": ["active", "clientTransferProhibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "2018-04-12T10:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2028-04-12T10:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2024-01-10T14:22:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Acme Technologies Ltd Admin"]]],
            },
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Demo Registrar Services Inc."]]],
            },
        ],
    },
    "crice.demo": {
        "objectClassName": "domain",
        "handle": "DOM-CRICE-DEMO-002",
        "ldhName": "crice.demo",
        "status": ["active"],
        "events": [
            {"eventAction": "registration", "eventDate": "2023-08-01T08:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-01T08:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "CRICE Technologies Private Limited"]]],
            }
        ],
    },
    "example.com": {
        "objectClassName": "domain",
        "handle": "2336799_DOMAIN_COM-VRSN",
        "ldhName": "example.com",
        "status": ["clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Internet Assigned Numbers Authority"]]],
            }
        ],
    },
}


@dataclass
class RDAPResult:
    domain: str
    status: str  # "FOUND", "NOT_FOUND", "FAILED"
    source_url: str
    raw_content: Optional[str] = None
    snapshot_hash: Optional[str] = None
    error_detail: Optional[str] = None
    summary: Optional[dict[str, Any]] = None


def normalize_and_validate_domain(raw_domain: str) -> str:
    """Validate and normalize domain name. Rejects schemes, paths, IPs, and invalid formats."""
    d = raw_domain.strip().lower()
    if not d:
        raise ValueError("Domain cannot be empty.")
    if d.startswith("http://") or d.startswith("https://") or "/" in d:
        raise ValueError("Enter a domain name without URL scheme or path (e.g. example.com).")
    if ":" in d:
        raise ValueError("Domain cannot contain port numbers.")
    if d.endswith("."):
        d = d[:-1]
    if not DOMAIN_REGEX.match(d):
        raise ValueError(f"Invalid domain format: {raw_domain!r}. Expected e.g. company.com")
    # Reject pure IP addresses
    parts = d.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        raise ValueError(f"IP addresses are not permitted: {raw_domain!r}. Enter a domain name.")
    return d


def extract_rdap_summary(data: dict[str, Any]) -> dict[str, Any]:
    """Extract key human-readable fields from standard RDAP JSON."""
    summary: dict[str, Any] = {
        "ldhName": data.get("ldhName"),
        "handle": data.get("handle"),
        "status": data.get("status", []),
        "events": {},
        "entities": [],
    }
    for ev in data.get("events", []):
        act = ev.get("eventAction")
        dt = ev.get("eventDate")
        if act and dt:
            summary["events"][act] = dt

    for ent in data.get("entities", []):
        roles = ent.get("roles", [])
        name = None
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
            for prop in vcard[1]:
                if isinstance(prop, list) and len(prop) > 3 and prop[0] == "fn":
                    name = prop[3]
                    break
        summary["entities"].append({"roles": roles, "name": name})
    return summary


def fetch_domain_rdap(
    domain: str,
    http_client: Optional[httpx.Client] = None,
) -> RDAPResult:
    """
    Query RDAP for domain details.
    Supports deterministic offline execution via CRICE_OFFLINE_RDAP or .demo domains.
    Returns structured RDAPResult with status FOUND, NOT_FOUND, or FAILED.
    """
    clean_domain = normalize_and_validate_domain(domain)
    target_url = f"https://rdap.org/domain/{clean_domain}"

    # 1. Deterministic offline/demo check
    is_offline_forced = os.getenv("CRICE_OFFLINE_RDAP") == "1"
    if is_offline_forced or clean_domain in _DEMO_RDAP_FIXTURES or clean_domain.endswith(".demo"):
        if clean_domain in _DEMO_RDAP_FIXTURES:
            payload = _DEMO_RDAP_FIXTURES[clean_domain]
            canonical_json = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
            h = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest().lower()
            return RDAPResult(
                domain=clean_domain,
                status="FOUND",
                source_url=target_url,
                raw_content=canonical_json,
                snapshot_hash=h,
                summary=extract_rdap_summary(payload),
            )
        elif clean_domain.startswith("notfound") or clean_domain == "notfound.demo":
            return RDAPResult(
                domain=clean_domain,
                status="NOT_FOUND",
                source_url=target_url,
            )
        elif clean_domain.startswith("failed") or clean_domain == "failed.demo":
            return RDAPResult(
                domain=clean_domain,
                status="FAILED",
                source_url=target_url,
                error_detail="Simulated RDAP registry connection timeout (504 Gateway Timeout)",
            )
        elif is_offline_forced:
            # Synthetic offline fallback for any unlisted domain under offline mode
            return RDAPResult(
                domain=clean_domain,
                status="NOT_FOUND",
                source_url=target_url,
            )

    # 2. Live HTTP query
    headers = {
        "Accept": "application/rdap+json, application/json",
        "User-Agent": "CRICE-OSINT-Engine/1.0",
    }
    timeout = 8.0

    try:
        if http_client:
            res = http_client.get(target_url, headers=headers, timeout=timeout)
        else:
            with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                res = client.get(target_url, headers=headers)

        if res.status_code == 200:
            try:
                data = res.json()
            except Exception as e:
                return RDAPResult(
                    domain=clean_domain,
                    status="FAILED",
                    source_url=target_url,
                    error_detail=f"Malformed RDAP response (non-JSON payload): {e}",
                )
            canonical_json = json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False)
            h = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest().lower()
            return RDAPResult(
                domain=clean_domain,
                status="FOUND",
                source_url=target_url,
                raw_content=canonical_json,
                snapshot_hash=h,
                summary=extract_rdap_summary(data),
            )
        elif res.status_code == 404:
            return RDAPResult(
                domain=clean_domain,
                status="NOT_FOUND",
                source_url=target_url,
            )
        else:
            return RDAPResult(
                domain=clean_domain,
                status="FAILED",
                source_url=target_url,
                error_detail=f"RDAP registry returned HTTP {res.status_code}: {res.text[:200]}",
            )
    except httpx.TimeoutException:
        return RDAPResult(
            domain=clean_domain,
            status="FAILED",
            source_url=target_url,
            error_detail="RDAP query timed out after 8.0s (degraded mode)",
        )
    except Exception as exc:
        return RDAPResult(
            domain=clean_domain,
            status="FAILED",
            source_url=target_url,
            error_detail=f"RDAP query failed: {type(exc).__name__}: {exc}",
        )
