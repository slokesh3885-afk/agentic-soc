from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.evidence import EvidenceModel
from app.schemas.evidence import (
    EvidenceCreate,
    EvidenceResponse,
    EvidenceIntegrityCheck,
    EvidenceControlPlaneItem,
    EvidenceControlPlaneSummary,
    EvidentiaryClaim,
    AttributionPolicyStatus,
    BatchVerificationResponse,
)
from app.services.evidence_service import (
    create_evidence,
    get_evidence_by_investigation,
    get_evidence_by_id,
    verify_evidence_integrity,
)
from app.services.evidence_control_plane_service import (
    get_control_plane_evidence,
    get_control_plane_summary,
    get_all_evidentiary_claims,
    get_attribution_policy_status,
    verify_all_evidence_batch,
)

router = APIRouter(tags=["evidence"])


def _to_evidence_response(model: EvidenceModel) -> EvidenceResponse:
    """Helper to convert EvidenceModel to validated Pydantic response."""
    return EvidenceResponse(
        id=model.id,
        investigation_id=model.investigation_id,
        evidence_type=model.evidence_type,
        source=model.source,
        timestamp=model.timestamp,
        query=model.query or "",
        raw_output=model.raw_output,
        content_hash=model.content_hash,
        status=model.status,
        created_at=model.created_at,
        integrity_verified=True,
    )


@router.post(
    "/investigations/{investigation_id}/evidence",
    response_model=EvidenceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Append new evidence to an investigation",
)
def add_evidence_to_investigation(
    investigation_id: str,
    data: EvidenceCreate,
    db: Session = Depends(get_db),
):
    """
    Append an immutable evidence item to an existing investigation.
    Validates investigation existence (returns 404 if missing).
    Autonomously generates sequential ID (e.g. E-001) and computes SHA-256 content hash.
    Increments parent investigation's evidence count.
    """
    model = create_evidence(db, investigation_id, data)
    return _to_evidence_response(model)


@router.get(
    "/investigations/{investigation_id}/evidence",
    response_model=List[EvidenceResponse],
    summary="List all evidence items for an investigation",
)
def list_investigation_evidence(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieve all evidence objects linked to an existing investigation.
    Returns 404 if the investigation does not exist.
    """
    models = get_evidence_by_investigation(db, investigation_id)
    return [_to_evidence_response(m) for m in models]


# ==============================================================================
# Module 3R: Evidence Control Plane & Claims Corroboration Engine Endpoints
# ==============================================================================

@router.get(
    "/evidence/summary",
    response_model=EvidenceControlPlaneSummary,
    summary="Get Evidence Control Plane KPI Summary",
)
def get_control_plane_summary_endpoint(db: Session = Depends(get_db)):
    """Retrieve global KPIs for the Evidence Control Plane."""
    return get_control_plane_summary(db)


@router.get(
    "/evidence/claims",
    response_model=List[EvidentiaryClaim],
    summary="Get Claims Corroboration Matrix",
)
def get_claims_matrix_endpoint(
    investigation_id: Optional[str] = Query(None, description="Filter by investigation ID"),
):
    """Retrieve evidentiary claims matrix showing supported vs refused conclusions."""
    return get_all_evidentiary_claims(investigation_id)


@router.get(
    "/evidence/attribution-policy",
    response_model=AttributionPolicyStatus,
    summary="Get Threat Actor Attribution Policy & Guard Status",
)
def get_attribution_policy_endpoint():
    """Evaluate and retrieve Threat Actor Attribution Policy status."""
    return get_attribution_policy_status()


@router.post(
    "/evidence/verify-batch",
    response_model=BatchVerificationResponse,
    summary="Batch verify all evidence items and calculate Merkle root",
)
def verify_evidence_batch_endpoint(db: Session = Depends(get_db)):
    """Recalculate SHA-256 for all evidence items in database and verify Merkle root."""
    return verify_all_evidence_batch(db)


@router.get(
    "/evidence",
    response_model=List[EvidenceControlPlaneItem],
    summary="List all evidence items in the Control Plane",
)
def list_control_plane_evidence(
    investigation_id: Optional[str] = Query(None, description="Filter by investigation ID"),
    evidence_type: Optional[str] = Query(None, description="Filter by evidence type"),
    source: Optional[str] = Query(None, description="Filter by source system"),
    reliability: Optional[str] = Query(None, description="Filter by reliability status"),
    search: Optional[str] = Query(None, description="Search term in evidence ID, source, or output"),
    limit: int = Query(100, ge=1, le=500, description="Max items to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    db: Session = Depends(get_db),
):
    """Retrieve paginated, filtered evidence items formatted for the Evidence Control Plane."""
    return get_control_plane_evidence(
        db=db,
        investigation_id=investigation_id,
        evidence_type=evidence_type,
        source=source,
        reliability=reliability,
        search=search,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/evidence/{evidence_id}",
    response_model=EvidenceResponse,
    summary="Get a single evidence item by ID",
)
def get_single_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieve an individual evidence object by its global ID (e.g. E-001).
    Returns 404 if not found.
    """
    model = get_evidence_by_id(db, evidence_id)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence with ID '{evidence_id}' not found.",
        )
    return _to_evidence_response(model)


@router.get(
    "/evidence/{evidence_id}/verify",
    response_model=EvidenceIntegrityCheck,
    summary="Cryptographically verify evidence integrity",
)
def verify_single_evidence_integrity(
    evidence_id: str,
    db: Session = Depends(get_db),
):
    """
    Recalculates the SHA-256 hash of the raw_output on the fly and verifies
    against the stored content_hash, mathematically proving tamper-evidence.
    """
    return verify_evidence_integrity(db, evidence_id)
