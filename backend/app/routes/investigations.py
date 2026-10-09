import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.investigation import InvestigationModel
from app.schemas.investigation import InvestigationCreate, InvestigationResponse
from app.services.investigation_service import (
    get_all_investigations,
    get_investigation_by_id,
    create_investigation,
)

router = APIRouter(prefix="/investigations", tags=["investigations"])


def _to_response_schema(model: InvestigationModel) -> InvestigationResponse:
    """Helper to convert SQLAlchemy model to validated Pydantic response."""
    corroboration = []
    if model.evidence_corroboration:
        try:
            corroboration = json.loads(model.evidence_corroboration)
        except Exception:
            corroboration = []

    return InvestigationResponse(
        id=model.id,
        alert_name=model.alert_name,
        target_host=model.target_host,
        severity=model.severity,
        event_timestamp=model.event_timestamp,
        description=model.description or "",
        status=model.status,
        evidence_count=model.evidence_count,
        trust_score=model.trust_score,
        created_at=model.created_at,
        assigned_agent=model.assigned_agent or "Host Triage Agent",
        mitre_technique=model.mitre_technique or "",
        evidence_corroboration=corroboration,
    )


@router.get("", response_model=List[InvestigationResponse])
@router.get("/", response_model=List[InvestigationResponse], include_in_schema=False)
def list_investigations(db: Session = Depends(get_db)):
    """Return all investigations sorted by newest first."""
    models = get_all_investigations(db)
    return [_to_response_schema(m) for m in models]


@router.get("/{investigation_id}", response_model=InvestigationResponse)
def get_single_investigation(investigation_id: str, db: Session = Depends(get_db)):
    """Return a single investigation by ID."""
    model = get_investigation_by_id(db, investigation_id)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found.",
        )
    return _to_response_schema(model)


@router.post("", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=InvestigationResponse, status_code=status.HTTP_201_CREATED, include_in_schema=False)
def add_investigation(
    data: InvestigationCreate,
    db: Session = Depends(get_db),
):
    """
    Create a new investigation.
    The ID is generated autonomously by the backend (e.g. INV-007).
    """
    created_model = create_investigation(db, data)
    return _to_response_schema(created_model)
