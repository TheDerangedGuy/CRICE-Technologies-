"""
app/collect/charter.py – Source Charter registry and seeding.

Only chartered sources may be queried in CRICE.
Each source defines code, name, owner, tier, default_reliability,
collection_mode, legal_basis, and active status.
"""
from app.models import CollectionMode, SourceCharter, SourceReliability, SourceTier

DEFAULT_CHARTERED_SOURCES = [
    {
        "code": "DOMAIN_RDAP",
        "name": "Domain RDAP Registry",
        "owner": "ICANN / Registry RDAP",
        "tier": SourceTier.A.value,
        "default_reliability": SourceReliability.A.value,
        "collection_mode": CollectionMode.AUTOMATED.value,
        "legal_basis": "DPDP Act 2023 s.3(c)(ii) - Public domain registry under legal obligation",
        "is_active": True,
    },
    {
        "code": "MCA_MANUAL",
        "name": "MCA21 Corporate Filings",
        "owner": "Ministry of Corporate Affairs (MCA)",
        "tier": SourceTier.A.value,
        "default_reliability": SourceReliability.A.value,
        "collection_mode": CollectionMode.MANUAL_CAPTURE.value,
        "legal_basis": "Companies Act 2013 s.399 - Statutory right of public inspection",
        "is_active": True,
    },
    {
        "code": "ECOURTS_MANUAL",
        "name": "eCourts Case & Order Search",
        "owner": "eCourts Services / High Courts / NCLT",
        "tier": SourceTier.A.value,
        "default_reliability": SourceReliability.A.value,
        "collection_mode": CollectionMode.MANUAL_CAPTURE.value,
        "legal_basis": "Open Justice Principle - Public record judicial orders and filings",
        "is_active": True,
    },
    {
        "code": "GST_MANUAL",
        "name": "GST Taxpayer Portal",
        "owner": "GSTN / Central Board of Indirect Taxes",
        "tier": SourceTier.A.value,
        "default_reliability": SourceReliability.A.value,
        "collection_mode": CollectionMode.MANUAL_CAPTURE.value,
        "legal_basis": "CGST Act 2017 s.158 - Public taxpayer search and compliance check",
        "is_active": True,
    },
    {
        "code": "NEWS_MANUAL",
        "name": "Financial Press & Media Archive",
        "owner": "Reputable Financial Press Archive",
        "tier": SourceTier.C.value,
        "default_reliability": SourceReliability.C.value,
        "collection_mode": CollectionMode.MANUAL_CAPTURE.value,
        "legal_basis": "Fair dealing for reporting of current affairs and public intelligence",
        "is_active": True,
    },
]


def seed_source_charter(db) -> list[SourceCharter]:
    """Idempotently seed the official 5 default chartered sources."""
    sources = []
    for spec in DEFAULT_CHARTERED_SOURCES:
        sc = db.query(SourceCharter).filter(SourceCharter.code == spec["code"]).first()
        if not sc:
            sc = SourceCharter(**spec)
            db.add(sc)
            db.flush()
        sources.append(sc)
    db.commit()
    return sources
