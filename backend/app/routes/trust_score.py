"""
Trust Score Routes (Module 3G)
Agentic SOC — Auditable AI Security Operations Center

Exposes REST APIs for computing and retrieving the deterministic Evidence & Audit Quality Trust Score.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.canonical_case import CanonicalCaseJson
from app.schemas.trust_score import TrustScore
from app.services.trust_score_service import (
    get_investigation_trust_score,
    compute_trust_score,
)

router = APIRouter(tags=["trust_score"])


@router.get(
    "/investigations/{investigation_id}/trust-score",
    response_model=TrustScore,
    status_code=status.HTTP_200_OK,
    summary="Compute deterministic Evidence & Audit Quality Trust Score (Module 3G)",
)
def get_trust_score_for_investigation(
    investigation_id: str,
    case_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Compute and return the deterministic Evidence & Audit Quality Trust Score (0-100)
    for the specified investigation.
    Evaluates evidence coverage, SHA-256 integrity, claim corroboration, audit completeness,
    and applies transparent penalties for contradictions, unsupported claims, and uncertainties.
    Does NOT represent likelihood or probability of attack.
    """
    return get_investigation_trust_score(db, investigation_id, case_id)


@router.post(
    "/trust-score/calculate",
    response_model=TrustScore,
    status_code=status.HTTP_200_OK,
    summary="Calculate Trust Score from any Canonical Case JSON payload (Module 3G)",
)
def calculate_trust_score_from_payload(
    case: CanonicalCaseJson,
):
    """
    Stateless deterministic calculation endpoint.
    Computes Evidence & Audit Quality Trust Score (0-100) directly from a provided Canonical Case JSON.
    Guarantees that the same Case JSON always yields the exact same score.
    """
    return compute_trust_score(case)
