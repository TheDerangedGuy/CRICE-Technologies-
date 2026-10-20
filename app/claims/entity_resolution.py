"""
app/claims/entity_resolution.py – Alias and re-export of entity resolution & scoring.
"""
from app.claims.scoring import (
    normalize_identifier,
    normalize_indian_name,
    score_claim_entity_match,
)

__all__ = [
    "normalize_identifier",
    "normalize_indian_name",
    "score_claim_entity_match",
]
